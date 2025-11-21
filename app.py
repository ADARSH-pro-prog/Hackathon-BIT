"""
Medical Bill Analysis API - Flask Backend

A comprehensive Flask API for medical bill processing and analysis with:
- User authentication (JWT-based)
- OCR and PDF text extraction
- Medical bill analysis and validation
- Compliance checking against guidelines
- Report generation

Features:
- User registration and login with bcrypt password hashing
- JWT-based authentication for protected routes
- PDF and image OCR processing
- Table extraction from PDFs using pdfplumber
- Medical bill validation rules
- Guidelines compliance analysis
- HTML report generation

Notes:
- Uses SQLite database by default (configurable via DATABASE_URL)
- Requires optional dependencies for OCR (pytesseract, pdf2image, pdfplumber)
- For production: use HTTPS, rotate secrets, add input validation,
  implement token revocation/refresh, and use a WSGI server.
"""
from flask_cors import CORS


from datetime import timedelta, datetime, timezone
import os
import traceback
import re
import uuid
import json
import shutil

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (JWTManager, create_access_token,
								get_jwt_identity, jwt_required)
from flask_sqlalchemy import SQLAlchemy
import tempfile
import os
from werkzeug.utils import secure_filename

# Optional OCR imports: try to import at module level so routes can use them
# if present. If not available we set them to None and routes will return
# clear 501 responses explaining what's missing.
try:
    from PIL import Image as PIL_Image
except Exception:
    PIL_Image = None

try:
    import pytesseract
except Exception:
    pytesseract = None

try:
    import pdf2image
except Exception:
    pdf2image = None

try:
    import pdfplumber
except Exception:
    pdfplumber = None

# We'll import OCR libraries lazily inside the route as well to be defensive.


# Load environment variables from a .env file (optional, for development).
load_dotenv()


# -----------------------------
# Application configuration
# -----------------------------
app = Flask(__name__)
# after app = Flask(__name__)
CORS(app, supports_credentials=True)  

# Secret key and JWT settings. In production, set real secrets via env vars.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
# JWT and database configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', app.config['SECRET_KEY'])
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# SQLAlchemy (SQLite by default) and upload limits
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///flask_auth.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 8 * 1024 * 1024))

# Allowed extensions for image uploads
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif'}
# Allowed extensions for the upload-and-analyze endpoint (images + pdf)
ALLOWED_EXT = set(ALLOWED_IMAGE_EXTENSIONS) | {'.pdf'}

# Upload directory
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename: str) -> bool:
    """Return True if the filename has an allowed extension."""
    if not filename or '.' not in filename:
        return False
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXT

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
# -----------------------------
# User model for authentication
# -----------------------------
class User(db.Model):
    """Simple user model for authentication.

    Fields:
    - id: integer primary key
    - username: unique username
    - email: unique email address
    - password: bcrypt-hashed password (stored as string)
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


# Helper to lookup users by username
def find_user_by_username(username: str):
	"""Return a User instance by username or None."""
	return User.query.filter_by(username=username).first()

# -----------------------------
# Database Models for File Processing
# -----------------------------
class FileRecord(db.Model):
	"""Model for storing uploaded file metadata."""
	id = db.Column(db.String(36), primary_key=True)
	filename = db.Column(db.String(255), nullable=False)
	storage_path = db.Column(db.String(512), nullable=False)
	uploaded_at = db.Column(db.DateTime, nullable=False)
	status = db.Column(db.String(50), nullable=False, default="processing")
	size = db.Column(db.Integer, nullable=True)
	error = db.Column(db.Text, nullable=True)

class ExtractedDocument(db.Model):
	"""Model for storing extracted text and structured data from files."""
	id = db.Column(db.String(36), primary_key=True)
	file_id = db.Column(db.String(36), db.ForeignKey('file_record.id'), nullable=False)
	raw_text = db.Column(db.Text, nullable=True)
	structured_json = db.Column(db.Text, nullable=True)  # JSON stored as text
	confidence = db.Column(db.Float, nullable=True)
	processed_at = db.Column(db.DateTime, nullable=False)
	file_record = db.relationship('FileRecord', backref=db.backref('extracted', uselist=False))

class ValidationFlag(db.Model):
	"""Model for storing validation rule violations."""
	id = db.Column(db.String(36), primary_key=True)
	extracted_document_id = db.Column(db.String(36), db.ForeignKey('extracted_document.id'), nullable=False)
	rule_name = db.Column(db.String(100), nullable=False)
	severity = db.Column(db.String(20), nullable=False)  # 'error', 'warning', 'info'
	description = db.Column(db.Text, nullable=True)
	evidence = db.Column(db.Text, nullable=True)
	created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

# -----------------------------
# Helper Functions
# -----------------------------
def make_uuid(prefix: str = "") -> str:
	"""Generate a UUID string, optionally with a prefix."""
	uid = str(uuid.uuid4())
	return f"{prefix}-{uid}" if prefix else uid

def save_file_storage(file) -> tuple:
	"""Save uploaded file to storage and return (original_name, saved_path)."""
	orig_name = secure_filename(file.filename)
	ext = os.path.splitext(orig_name)[1] or '.bin'
	unique_name = f"{uuid.uuid4()}{ext}"
	saved_path = os.path.join(UPLOAD_FOLDER, unique_name)
	file.save(saved_path)
	return (orig_name, saved_path)

def try_imports() -> dict:
	"""Try to import optional libraries and return a dict of available modules."""
	modules = {}
	if pdfplumber:
		modules["pdfplumber"] = pdfplumber
	if pytesseract:
		modules["pytesseract"] = pytesseract
	if PIL_Image:
		modules["PIL"] = PIL_Image
	if pdf2image:
		modules["pdf2image"] = pdf2image
	return modules

def extract_tables_with_pdfplumber(pdf_path: str, modules: dict) -> tuple:
	"""Extract tables and text from PDF using pdfplumber.
	
	Returns:
		tuple: (line_items_list, extracted_text, tables_list)
	"""
	if not modules.get("pdfplumber"):
		return ([], "", [])
	
	try:
		plumber = modules["pdfplumber"]
		text_parts = []
		all_tables = []
		
		with plumber.open(pdf_path) as pdf:
			for page in pdf.pages:
				# Extract text
				page_text = page.extract_text()
				if page_text:
					text_parts.append(page_text)
				
				# Extract tables
				tables = page.extract_tables()
				if tables:
					all_tables.extend(tables)
		
		full_text = "\n".join(text_parts)
		# Use enhanced parser with table data
		line_items = enhanced_line_item_parser(full_text, all_tables)
		return (line_items, full_text, all_tables)
	except Exception as e:
		return ([], "", [])

def perform_ocr(file_path: str, modules: dict) -> str:
	"""Perform OCR on an image or PDF file.
	
	Returns:
		str: Extracted text
	"""
	if not modules.get("pytesseract") or not modules.get("PIL"):
		return ""
	
	try:
		pyt = modules["pytesseract"]
		pil = modules["PIL"]
		
		if file_path.lower().endswith(".pdf"):
			if not modules.get("pdf2image"):
				return ""
			pdf2img = modules["pdf2image"]
			pages = pdf2img.convert_from_path(file_path)
			text_parts = []
			for page in pages:
				text = pyt.image_to_string(page)
				text_parts.append(text)
			return "\n".join(text_parts)
		else:
			img = pil.open(file_path)
			return pyt.image_to_string(img)
	except Exception as e:
		return ""

def enhanced_line_item_parser(text: str, tables: list = None) -> list:
	"""Enhanced parser to extract line items from text and tables.
	
	Extracts: description, quantity, unit_price, total, tax, discount
	"""
	line_items = []
	
	# First, try to use table data if available
	if tables:
		for table in tables:
			if not table or len(table) < 2:
				continue
			
			# Try to identify header row
			headers = []
			header_row_idx = 0
			for i, row in enumerate(table[:3]):  # Check first 3 rows for headers
				if row and any(isinstance(cell, str) and cell.lower() in ['description', 'item', 'service', 'qty', 'quantity', 'price', 'amount', 'total'] for cell in row if cell):
					headers = [str(cell).lower().strip() if cell else f"col_{j}" for j, cell in enumerate(row)]
					header_row_idx = i
					break
			
			# Process data rows
			for row in table[header_row_idx + 1:]:
				if not row or not any(cell for cell in row if cell):
					continue
				
				item = {}
				for i, cell in enumerate(row):
					if i >= len(headers) or not cell:
						continue
					
					cell_str = str(cell).strip()
					header = headers[i] if i < len(headers) else f"col_{i}"
					
					# Map common header variations
					if any(x in header for x in ['desc', 'item', 'service', 'particular']):
						item["description"] = cell_str
					elif any(x in header for x in ['qty', 'quantity', 'qty.']):
						try:
							item["quantity"] = float(re.sub(r'[^\d.]', '', cell_str) or '1')
						except:
							item["quantity"] = 1.0
					elif any(x in header for x in ['unit', 'rate', 'price', 'unit price']):
						try:
							item["unit_price"] = float(re.sub(r'[^\d.]', '', cell_str) or '0')
						except:
							pass
					elif any(x in header for x in ['total', 'amount', 'amt']):
						try:
							item["total"] = float(re.sub(r'[^\d.]', '', cell_str) or '0')
						except:
							pass
					elif any(x in header for x in ['tax', 'gst', 'cgst', 'sgst']):
						try:
							item["tax"] = float(re.sub(r'[^\d.]', '', cell_str) or '0')
						except:
							pass
					elif any(x in header for x in ['discount', 'disc']):
						try:
							item["discount"] = float(re.sub(r'[^\d.]', '', cell_str) or '0')
						except:
							pass
					else:
						item[header] = cell_str
				
				if item.get("description") or any(k in item for k in ["total", "amount", "unit_price"]):
					# Calculate missing fields if possible
					if "quantity" not in item:
						item["quantity"] = 1.0
					if "unit_price" in item and "total" not in item:
						item["total"] = item["unit_price"] * item["quantity"]
					elif "total" in item and "unit_price" not in item and item["quantity"] > 0:
						item["unit_price"] = item["total"] / item["quantity"]
					
					line_items.append(item)
	
	# Fallback to text parsing if no table data or additional items needed
	lines = text.splitlines()
	for line in lines:
		line = line.strip()
		if not line or len(line) < 5:
			continue
		
		# Skip header lines and summary lines
		if any(x in line.lower() for x in ['description', 'qty', 'total', 'subtotal', 'grand total', '---', '===']):
			continue
		
		# Look for price patterns
		price_pattern = r'[\d,]+\.?\d*\s*(?:INR|Rs|₹|USD|\$)?'
		if re.search(price_pattern, line, re.IGNORECASE):
			# Try to extract components
			parts = re.split(r'\s{2,}|\t|  +', line)
			parts = [p.strip() for p in parts if p.strip()]
			
			if len(parts) >= 2:
				item = {
					"description": parts[0],
					"raw_line": line
				}
				
				# Extract numbers from the line
				numbers = re.findall(r'[\d,]+\.?\d*', line)
				if numbers:
					try:
						# Last number is usually total
						item["total"] = float(numbers[-1].replace(',', ''))
						if len(numbers) >= 2:
							item["quantity"] = float(numbers[0].replace(',', ''))
							if len(numbers) >= 3:
								item["unit_price"] = float(numbers[1].replace(',', ''))
							elif "quantity" in item and item["quantity"] > 0:
								item["unit_price"] = item["total"] / item["quantity"]
					except:
						pass
				
				if "total" in item or "description" in item:
					line_items.append(item)
	
	return line_items

def extract_patient_info(text: str) -> dict:
	"""Extract patient information using pattern matching."""
	info = {}
	text_lower = text.lower()
	
	# Patient name patterns
	name_patterns = [
		r'patient\s*name[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
		r'name\s*of\s*patient[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
		r'patient[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
		r'name[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)',
	]
	
	for pattern in name_patterns:
		match = re.search(pattern, text, re.IGNORECASE)
		if match:
			info["patient_name"] = match.group(1).strip()
			break
	
	# Patient ID
	id_match = re.search(r'patient\s*(?:id|no\.?|number)[:\s]+([A-Z0-9\-]+)', text, re.IGNORECASE)
	if id_match:
		info["patient_id"] = id_match.group(1).strip()
	
	# Age and gender
	age_match = re.search(r'age[:\s]+(\d+)', text, re.IGNORECASE)
	if age_match:
		info["age"] = age_match.group(1)
	
	gender_match = re.search(r'(?:sex|gender)[:\s]+([MF])', text, re.IGNORECASE)
	if gender_match:
		info["gender"] = gender_match.group(1)
	
	return info

def extract_hospital_info(text: str) -> dict:
	"""Extract hospital/clinic information."""
	info = {}
	
	# Hospital name - look for common patterns
	hospital_patterns = [
		r'(?:hospital|clinic|medical\s+center|healthcare)[:\s]+([A-Z][A-Za-z\s&]+)',
		r'([A-Z][A-Za-z\s&]+\s+(?:Hospital|Clinic|Medical\s+Center))',
	]
	
	for pattern in hospital_patterns:
		match = re.search(pattern, text)
		if match:
			info["hospital_name"] = match.group(1).strip()
			break
	
	# GST number
	gst_match = re.search(r'GST[:\s]+([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1})', text, re.IGNORECASE)
	if gst_match:
		info["gst_number"] = gst_match.group(1).strip()
	
	# Address
	address_match = re.search(r'address[:\s]+([^\n]{10,100})', text, re.IGNORECASE)
	if address_match:
		info["address"] = address_match.group(1).strip()
	
	return info

def extract_dates_enhanced(text: str) -> dict:
	"""Extract dates with multiple format support and validation."""
	dates = {}
	date_patterns = [
		r'(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',  # DD/MM/YYYY or DD-MM-YYYY
		r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',    # YYYY/MM/DD
		r'(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4})',  # DD Month YYYY
	]
	
	all_dates = []
	for pattern in date_patterns:
		all_dates.extend(re.findall(pattern, text, re.IGNORECASE))
	
	# Look for specific date types
	admission_patterns = [
		r'admission[:\s]+(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
		r'admitted[:\s]+(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
		r'admit[:\s]+(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
	]
	
	discharge_patterns = [
		r'discharge[:\s]+(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
		r'discharged[:\s]+(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
	]
	
	for pattern in admission_patterns:
		match = re.search(pattern, text, re.IGNORECASE)
		if match:
			dates["admission"] = match.group(1)
			break
	
	for pattern in discharge_patterns:
		match = re.search(pattern, text, re.IGNORECASE)
		if match:
			dates["discharge"] = match.group(1)
			break
	
	# If not found with labels, use first two dates found
	if "admission" not in dates and len(all_dates) > 0:
		dates["admission"] = all_dates[0]
	if "discharge" not in dates and len(all_dates) > 1:
		dates["discharge"] = all_dates[1]
	
	return dates

def verify_financial_calculations(text: str, line_items: list) -> list:
	"""Verify financial calculations and return issues."""
	issues = []
	
	# Extract totals from text
	subtotal_match = re.search(r'subtotal[:\s]+([\d,]+\.?\d*)', text, re.IGNORECASE)
	tax_match = re.search(r'(?:tax|gst)[:\s]+([\d,]+\.?\d*)', text, re.IGNORECASE)
	grand_total_match = re.search(r'(?:grand\s+)?total[:\s]+([\d,]+\.?\d*)', text, re.IGNORECASE)
	
	subtotal = float(subtotal_match.group(1).replace(',', '')) if subtotal_match else None
	tax = float(tax_match.group(1).replace(',', '')) if tax_match else None
	grand_total = float(grand_total_match.group(1).replace(',', '')) if grand_total_match else None
	
	# Calculate sum of line items
	calculated_subtotal = sum(item.get("total", 0) for item in line_items if isinstance(item.get("total"), (int, float)))
	
	# Verify calculations
	if subtotal and calculated_subtotal > 0:
		diff = abs(subtotal - calculated_subtotal)
		if diff > 0.01:  # Allow small rounding differences
			issues.append({
				"type": "calculation_mismatch",
				"description": f"Subtotal mismatch: Document shows {subtotal}, calculated {calculated_subtotal:.2f}",
				"severity": "error",
				"difference": diff
			})
	
	if subtotal and tax and grand_total:
		calculated_total = subtotal + tax
		diff = abs(grand_total - calculated_total)
		if diff > 0.01:
			issues.append({
				"type": "total_calculation_error",
				"description": f"Grand total calculation error: Expected {calculated_total:.2f}, found {grand_total}",
				"severity": "error",
				"difference": diff
			})
	
	# Check for negative amounts
	for item in line_items:
		if isinstance(item.get("total"), (int, float)) and item["total"] < 0:
			issues.append({
				"type": "negative_amount",
				"description": f"Negative amount found: {item.get('description', 'Unknown item')}",
				"severity": "error"
			})
	
	return issues

def run_validation_rules(session, ext_doc: ExtractedDocument):
	"""Run comprehensive validation rules on extracted document."""
	rules = []
	text = ext_doc.raw_text or ""
	text_lower = text.lower()
	
	# Parse structured data
	try:
		structured = json.loads(ext_doc.structured_json) if ext_doc.structured_json else {}
		line_items = structured.get("line_items", [])
	except:
		line_items = []
	
	# === DATA COMPLETENESS RULES ===
	
	# Rule 1: Empty text
	if not text or len(text.strip()) < 10:
		rules.append({
			"rule_name": "empty_text",
			"severity": "error",
			"description": "Extracted text is empty or too short",
			"evidence": f"Text length: {len(text)}"
		})
	
	# Rule 2: Missing patient name
	patient_info = extract_patient_info(text)
	if not patient_info.get("patient_name"):
		rules.append({
			"rule_name": "missing_patient_name",
			"severity": "warning",
			"description": "Patient name not detected in document",
			"evidence": "No patient name patterns found"
		})
	
	# Rule 3: Missing dates
	dates = extract_dates_enhanced(text)
	if not dates.get("admission") and not dates.get("discharge"):
		rules.append({
			"rule_name": "missing_dates",
			"severity": "warning",
			"description": "No dates detected in document",
			"evidence": "No date patterns found"
		})
	
	# Rule 4: Missing totals
	if not re.search(r'(?:total|amount|sum|grand).*?[\d,]+\.?\d*', text, re.IGNORECASE):
		rules.append({
			"rule_name": "missing_totals",
			"severity": "warning",
			"description": "No totals or amounts detected",
			"evidence": "No total/amount patterns found"
		})
	
	# Rule 5: Missing hospital/doctor name
	hospital_info = extract_hospital_info(text)
	if not hospital_info.get("hospital_name"):
		rules.append({
			"rule_name": "missing_hospital_name",
			"severity": "warning",
			"description": "Hospital/clinic name not detected",
			"evidence": "No hospital name patterns found"
		})
	
	# Rule 6: Missing invoice/bill number
	if not re.search(r'(?:invoice|bill|receipt)\s*(?:no\.?|number|#)[:\s]+[A-Z0-9\-]+', text, re.IGNORECASE):
		rules.append({
			"rule_name": "missing_bill_number",
			"severity": "info",
			"description": "Invoice/bill number not detected",
			"evidence": "No bill number patterns found"
		})
	
	# Rule 7: Missing GST number
	if not hospital_info.get("gst_number"):
		rules.append({
			"rule_name": "missing_gst_number",
			"severity": "warning",
			"description": "GST number not detected (may be required for taxable bills)",
			"evidence": "No GST number patterns found"
		})
	
	# === DATA QUALITY RULES ===
	
	# Rule 8: Date logic validation
	if dates.get("admission") and dates.get("discharge"):
		# Simple check - if dates are in same format, compare
		try:
			# Try to parse dates (simplified)
			ad = dates["admission"].replace('-', '/')
			dd = dates["discharge"].replace('-', '/')
			# Basic string comparison for same format
			if len(ad) == len(dd) and ad > dd:
				rules.append({
					"rule_name": "invalid_date_order",
					"severity": "error",
					"description": "Discharge date is before admission date",
					"evidence": f"Admission: {dates['admission']}, Discharge: {dates['discharge']}"
				})
		except:
			pass
	
	# Rule 9: Negative amounts
	negative_found = False
	for item in line_items:
		if isinstance(item.get("total"), (int, float)) and item["total"] < 0:
			negative_found = True
			break
	
	if negative_found:
		rules.append({
			"rule_name": "negative_amounts",
			"severity": "error",
			"description": "Negative amounts found in line items",
			"evidence": "One or more line items have negative values"
		})
	
	# Rule 10: Missing line item descriptions
	empty_descriptions = sum(1 for item in line_items if not item.get("description") or not item["description"].strip())
	if empty_descriptions > 0:
		rules.append({
			"rule_name": "empty_line_item_descriptions",
			"severity": "warning",
			"description": f"{empty_descriptions} line item(s) have empty descriptions",
			"evidence": f"Found {empty_descriptions} items without descriptions"
		})
	
	# === FINANCIAL VALIDATION RULES ===
	
	# Rule 11: Total calculation mismatch
	financial_issues = verify_financial_calculations(text, line_items)
	for issue in financial_issues:
		rules.append({
			"rule_name": issue["type"],
			"severity": issue["severity"],
			"description": issue["description"],
			"evidence": issue.get("difference", "")
		})
	
	# Rule 12: Duplicate line items (simple check)
	if len(line_items) > 1:
		descriptions = [item.get("description", "").lower().strip() for item in line_items if item.get("description")]
		duplicates = [d for d in descriptions if descriptions.count(d) > 1]
		if duplicates:
			rules.append({
				"rule_name": "duplicate_line_items",
				"severity": "warning",
				"description": f"Potential duplicate line items found: {', '.join(set(duplicates[:3]))}",
				"evidence": f"Found {len(set(duplicates))} duplicate description(s)"
			})
	
	# Rule 13: Unusual charges (flag very high amounts)
	if line_items:
		totals = [item.get("total", 0) for item in line_items if isinstance(item.get("total"), (int, float))]
		if totals:
			avg = sum(totals) / len(totals)
			high_items = [item for item in line_items if isinstance(item.get("total"), (int, float)) and item["total"] > avg * 10]
			if high_items:
				rules.append({
					"rule_name": "unusual_charges",
					"severity": "info",
					"description": f"{len(high_items)} item(s) with unusually high charges detected",
					"evidence": f"Items exceed 10x average charge amount"
				})
	
	# Rule 14: Missing tax breakdown
	if re.search(r'total|grand\s+total', text, re.IGNORECASE) and not re.search(r'(?:cgst|sgst|igst|tax\s+breakdown)', text, re.IGNORECASE):
		rules.append({
			"rule_name": "missing_tax_breakdown",
			"severity": "info",
			"description": "Tax breakdown (CGST/SGST/IGST) not found",
			"evidence": "Total found but no tax breakdown detected"
		})
	
	# Rule 15: Currency consistency
	currencies = re.findall(r'(INR|Rs|₹|USD|\$)', text, re.IGNORECASE)
	if len(set(c.upper() for c in currencies)) > 1:
		rules.append({
			"rule_name": "currency_inconsistency",
			"severity": "warning",
			"description": "Multiple currencies detected in document",
			"evidence": f"Found: {', '.join(set(currencies))}"
		})
	
	# Create ValidationFlag records
	for rule in rules:
		flag = ValidationFlag(
			id=make_uuid("flag"),
			extracted_document_id=ext_doc.id,
			rule_name=rule["rule_name"],
			severity=rule["severity"],
			description=rule["description"],
			evidence=str(rule.get("evidence", "")),
			created_at=datetime.now(timezone.utc)
		)
		session.add(flag)
	
	session.commit()

def analyze_extracted_text_against_guidelines(text: str, guidelines_path: str = None) -> dict:
	"""Analyze extracted text against guidelines PDF.
	
	This is a simplified version that returns basic analysis.
	"""
	analysis = {
		"summary": {
			"compliance_score": 0.75,
			"issues_found": [],
			"recommendations": []
		},
		"details": {}
	}
	
	# Simple heuristic checks
	if not text or len(text.strip()) < 20:
		analysis["summary"]["issues_found"].append("Insufficient text extracted")
		analysis["summary"]["compliance_score"] = 0.3
	else:
		# Check for common billing elements
		checks = {
			"has_patient_info": bool(re.search(r'patient|name', text, re.IGNORECASE)),
			"has_dates": bool(re.search(r'\d{1,2}[-/]\d{1,2}[-/]\d{2,4}', text)),
			"has_amounts": bool(re.search(r'[\d,]+\.?\d*\s*(?:INR|Rs|₹)', text, re.IGNORECASE)),
			"has_line_items": bool(re.search(r'description|item|service', text, re.IGNORECASE))
		}
		
		analysis["details"]["checks"] = checks
		score = sum(checks.values()) / len(checks) if checks else 0
		analysis["summary"]["compliance_score"] = round(score, 2)
	
	return analysis

def generate_report(session, ext_doc: ExtractedDocument) -> str:
	"""Generate a PDF/HTML report for the extracted document.
	
	Returns:
		str: Path to generated report file, or None if generation fails
	"""
	try:
		# Simple HTML report generation
		report_dir = os.path.join(os.path.dirname(__file__), 'reports')
		os.makedirs(report_dir, exist_ok=True)
		
		report_id = make_uuid("report")
		report_path = os.path.join(report_dir, f"{report_id}.html")
		
		# Get validation flags
		flags = ValidationFlag.query.filter(ValidationFlag.extracted_document_id == ext_doc.id).all()
		
		# Parse structured data for report
		try:
			structured_data = json.loads(ext_doc.structured_json) if ext_doc.structured_json else {}
			line_items = structured_data.get("line_items", [])
			meta = structured_data.get("meta", {})
		except:
			line_items = []
			meta = {}
		
		# Group flags by severity
		error_flags = [f for f in flags if f.severity == "error"]
		warning_flags = [f for f in flags if f.severity == "warning"]
		info_flags = [f for f in flags if f.severity == "info"]
		
		# Generate enhanced HTML report
		html_content = f"""
<!DOCTYPE html>
<html>
<head>
	<title>Medical Bill Analysis Report</title>
	<meta charset="UTF-8">
	<style>
		* {{ box-sizing: border-box; }}
		body {{ 
			font-family: 'Segoe UI', Arial, sans-serif; 
			margin: 0; 
			padding: 20px; 
			background: #f5f5f5;
			line-height: 1.6;
		}}
		.container {{
			max-width: 1200px;
			margin: 0 auto;
			background: white;
			padding: 30px;
			box-shadow: 0 2px 10px rgba(0,0,0,0.1);
		}}
		h1 {{ 
			color: #2c3e50; 
			border-bottom: 3px solid #3498db;
			padding-bottom: 10px;
		}}
		h2 {{
			color: #34495e;
			margin-top: 30px;
			border-left: 4px solid #3498db;
			padding-left: 15px;
		}}
		.metadata {{
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
			gap: 15px;
			margin: 20px 0;
			padding: 15px;
			background: #ecf0f1;
			border-radius: 5px;
		}}
		.metadata-item {{
			display: flex;
			flex-direction: column;
		}}
		.metadata-label {{
			font-weight: bold;
			color: #7f8c8d;
			font-size: 0.9em;
		}}
		.metadata-value {{
			color: #2c3e50;
			font-size: 1.1em;
		}}
		.flag {{
			margin: 10px 0;
			padding: 15px;
			border-left: 4px solid #ccc;
			background: #f8f9fa;
			border-radius: 4px;
		}}
		.flag.error {{
			border-color: #e74c3c;
			background: #fee;
		}}
		.flag.warning {{
			border-color: #f39c12;
			background: #fff8e1;
		}}
		.flag.info {{
			border-color: #3498db;
			background: #e3f2fd;
		}}
		.flag-title {{
			font-weight: bold;
			font-size: 1.1em;
			margin-bottom: 5px;
		}}
		.flag-evidence {{
			font-size: 0.9em;
			color: #7f8c8d;
			margin-top: 5px;
		}}
		.summary-box {{
			background: #e8f5e9;
			padding: 15px;
			border-radius: 5px;
			margin: 20px 0;
		}}
		.summary-box.error {{
			background: #ffebee;
		}}
		.summary-box.warning {{
			background: #fff3e0;
		}}
		table {{
			width: 100%;
			border-collapse: collapse;
			margin: 20px 0;
		}}
		table th, table td {{
			padding: 12px;
			text-align: left;
			border-bottom: 1px solid #ddd;
		}}
		table th {{
			background: #3498db;
			color: white;
			font-weight: bold;
		}}
		table tr:hover {{
			background: #f5f5f5;
		}}
		pre {{
			background: #f8f9fa;
			padding: 15px;
			border-radius: 5px;
			overflow-x: auto;
			border: 1px solid #dee2e6;
		}}
		.confidence-badge {{
			display: inline-block;
			padding: 5px 15px;
			border-radius: 20px;
			font-weight: bold;
			background: #3498db;
			color: white;
		}}
		.confidence-badge.high {{ background: #27ae60; }}
		.confidence-badge.medium {{ background: #f39c12; }}
		.confidence-badge.low {{ background: #e74c3c; }}
	</style>
</head>
<body>
	<div class="container">
		<h1>Medical Bill Analysis Report</h1>
		
		<div class="metadata">
			<div class="metadata-item">
				<span class="metadata-label">Document ID</span>
				<span class="metadata-value">{ext_doc.id}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Processed At</span>
				<span class="metadata-value">{ext_doc.processed_at}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Confidence Score</span>
				<span class="metadata-value">
					<span class="confidence-badge {'high' if (ext_doc.confidence or 0) >= 0.8 else 'medium' if (ext_doc.confidence or 0) >= 0.5 else 'low'}">
						{(ext_doc.confidence or 0) * 100:.0f}%
					</span>
				</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Total Validation Flags</span>
				<span class="metadata-value">{len(flags)} ({len(error_flags)} errors, {len(warning_flags)} warnings, {len(info_flags)} info)</span>
			</div>
		</div>
		
		<h2>Executive Summary</h2>
		<div class="summary-box {'error' if error_flags else 'warning' if warning_flags else ''}">
			<p><strong>Status:</strong> {'❌ Issues Found' if error_flags else '⚠️ Warnings' if warning_flags else '✅ No Critical Issues'}</p>
			<p><strong>Total Flags:</strong> {len(flags)} ({len(error_flags)} errors, {len(warning_flags)} warnings, {len(info_flags)} informational)</p>
			<p><strong>Line Items Extracted:</strong> {len(line_items)}</p>
		</div>
		
		<h2>Extracted Information</h2>
		<div class="metadata">
			<div class="metadata-item">
				<span class="metadata-label">Patient Name</span>
				<span class="metadata-value">{meta.get('detected_patient_name', 'Not detected')}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Patient ID</span>
				<span class="metadata-value">{meta.get('detected_patient_id', 'Not detected')}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Hospital</span>
				<span class="metadata-value">{meta.get('detected_hospital', 'Not detected')}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Admission Date</span>
				<span class="metadata-value">{meta.get('detected_dates', {}).get('admission', 'Not detected')}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">Discharge Date</span>
				<span class="metadata-value">{meta.get('detected_dates', {}).get('discharge', 'Not detected')}</span>
			</div>
			<div class="metadata-item">
				<span class="metadata-label">GST Number</span>
				<span class="metadata-value">{meta.get('detected_gst_number', 'Not detected')}</span>
			</div>
		</div>
		
		<h2>Validation Flags</h2>
		{'<h3 style="color: #e74c3c;">Errors</h3>' + ''.join([f'<div class="flag error"><div class="flag-title">{f.rule_name}</div><div>{f.description}</div><div class="flag-evidence">Evidence: {f.evidence}</div></div>' for f in error_flags]) if error_flags else ''}
		{'<h3 style="color: #f39c12;">Warnings</h3>' + ''.join([f'<div class="flag warning"><div class="flag-title">{f.rule_name}</div><div>{f.description}</div><div class="flag-evidence">Evidence: {f.evidence}</div></div>' for f in warning_flags]) if warning_flags else ''}
		{'<h3 style="color: #3498db;">Information</h3>' + ''.join([f'<div class="flag info"><div class="flag-title">{f.rule_name}</div><div>{f.description}</div><div class="flag-evidence">Evidence: {f.evidence}</div></div>' for f in info_flags]) if info_flags else ''}
		{'' if flags else '<p>✅ No validation flags. All checks passed.</p>'}
		
		<h2>Line Items</h2>
		{'<table><thead><tr><th>Description</th><th>Quantity</th><th>Unit Price</th><th>Total</th></tr></thead><tbody>' + ''.join([f'<tr><td>{item.get("description", "N/A")}</td><td>{item.get("quantity", "N/A")}</td><td>{item.get("unit_price", "N/A")}</td><td>{item.get("total", "N/A")}</td></tr>' for item in line_items[:50]]) + '</tbody></table>' if line_items else '<p>No line items extracted.</p>'}
		
		<h2>Structured Data (JSON)</h2>
		<pre>{json.dumps(structured_data, indent=2, ensure_ascii=False)}</pre>
		
		<h2>Raw Text (Preview - First 2000 characters)</h2>
		<pre>{ext_doc.raw_text[:2000] if ext_doc.raw_text else 'No text extracted'}...</pre>
	</div>
</body>
</html>
"""
		
		with open(report_path, 'w', encoding='utf-8') as f:
			f.write(html_content)
		
		return report_path
	except Exception as e:
		return None
# -----------------------------
@app.route('/register', methods=['POST'])
def register():
	"""Register a new user.

	Expected JSON body: {"username": "alice", "email": "a@b.com", "password": "..."}

	The route performs basic validation, checks for duplicates, hashes the
	password using bcrypt, saves the user to the SQLite DB via SQLAlchemy,
	and returns the created user's id and username.
	"""
	data = request.get_json(force=True)
	username = (data.get('username') or '').strip()
	email = (data.get('email') or '').strip().lower()
	password = data.get('password') or ''

	if not username or not email or not password:
		return jsonify({'msg': 'username, email and password are required'}), 400

	# Prevent duplicate usernames or emails
	if User.query.filter((User.username == username) | (User.email == email)).first():
		return jsonify({'msg': 'username or email already exists'}), 409

	# Hash the password and create the user
	hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
	user = User(username=username, email=email, password=hashed_pw)
	db.session.add(user)
	db.session.commit()

	return jsonify({'msg': 'user created', 'user_id': user.id, 'username': username}), 201


@app.route('/login', methods=['POST'])
def login():
	"""Authenticate user and return a JWT access token.

	Expected JSON body: {"username": "alice", "password": "..."}
	"""
	data = request.get_json(force=True)
	username = (data.get('username') or '').strip()
	password = data.get('password') or ''

	if not username or not password:
		return jsonify({'msg': 'username and password required'}), 400

	user = find_user_by_username(username)
	if not user or not bcrypt.check_password_hash(user.password, password):
		# Generic message to avoid revealing which field was incorrect
		return jsonify({'msg': 'invalid credentials'}), 401

	# Create JWT. Use the integer user id as identity (stringified by JWT lib).
	access_token = create_access_token(identity=str(user.id))
	return jsonify({'access_token': access_token, 'username': user.username}), 200


@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
	"""Protected route returning basic user info.

	Callers must include Authorization: Bearer <token> header.
	"""
	user_id = get_jwt_identity()

	# Convert identity back to integer and query the DB.
	try:
		uid = int(user_id)
	except (TypeError, ValueError):
		return jsonify({'msg': 'invalid token identity'}), 400

	user = User.query.get(uid)
	if not user:
		return jsonify({'msg': 'user not found'}), 404

	user_info = {
		'user_id': user.id,
		'username': user.username,
		'email': user.email,
	}
	return jsonify({'profile': user_info}), 200


# -----------------------------
# OCR endpoint
# -----------------------------
# OCR libraries are imported lazily inside the route to avoid startup failures

@app.route('/ocr', methods=['POST'])
@jwt_required()
def ocr():
    """
    Extracts text and other medical billing details from uploaded files.
    
    This route allows users to upload multiple files for OCR processing. It supports extraction of 
    text, tables, line items, totals, taxes, and specific details like patient name, hospital name, 
    admission/discharge dates, and more.
    
    Returns:
        JSON response with extracted data on success, error message on failure.
    """
    user_id = get_jwt_identity()

    # Convert identity back to integer and query the DB.
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return jsonify({'msg': 'invalid token identity'}), 400

    user = User.query.get(uid)
    if not user:
        return jsonify({'msg': 'user not found'}), 404

    files = request.files.getlist('files[]')
    results = []

    for file in files:
        filename = secure_filename(file.filename)
        suffix = os.path.splitext(filename)[1] or '.png'
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)

        # Use module-level optional imports (set at startup). This avoids
        # repeated import attempts and ensures we observe installed packages.
        if PIL_Image is None:
            return jsonify({'msg': 'Pillow library not available'}), 501
        # pytesseract may be installed as a Python package but still require the
        # system tesseract binary to be present; we check availability later.
        if pytesseract is None:
            return jsonify({'msg': 'pytesseract not available for OCR'}), 501
        # pdf2image is optional (only for PDFs)
        # pdf2image may require poppler on the system; if not installed, we
        # will return a clear error when trying to handle PDFs.
        try:
            file.save(tmp.name)

            # Optionally compress and optimize images
            if suffix.lower() in ['.jpg', '.jpeg', '.png']:
                try:
                    img = PIL_Image.open(tmp.name)
                    img.save(tmp.name, optimize=True, quality=85)
                except Exception:
                    # non-fatal: continue with original file
                    pass

            # Handle multi-page PDFs if required
            if suffix.lower() == '.pdf':
                if not pdf2image:
                    results.append({
                        'filename': filename, 
                        'error': 'pdf handling requires pdf2image/poppler, which is not available'
                    })
                else:
                    try:
                        pages = pdf2image.convert_from_path(tmp.name)
                        for i, page in enumerate(pages):
                            if not pytesseract:
                                results.append({
                                    'filename': filename, 
                                    'page_number': i+1,
                                    'error': 'pytesseract not available for OCR'
                                })
                            else:
                                try:
                                    text = pytesseract.image_to_string(page)
                                    results.append({'filename': filename, 'page_number': i+1, 'text': text})
                                except Exception as ocr_err:
                                    results.append({
                                        'filename': filename, 
                                        'page_number': i+1,
                                        'error': f'OCR failed: {str(ocr_err)}'
                                    })
                    except Exception as pdf_err:
                        results.append({
                            'filename': filename, 
                            'error': f'PDF conversion failed: {str(pdf_err)}. Is Poppler installed?'
                        })
            else:
                if not pytesseract:
                    return jsonify({'msg': 'pytesseract not available for OCR'}), 501
                text = pytesseract.image_to_string(PIL_Image.open(tmp.name))
                results.append({'filename': filename, 'text': text})

        except Exception as e:
            return jsonify({'msg': 'error during OCR', 'error': str(e)}), 500
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

    return jsonify({'results': results}), 200

# Endpoint: Upload + Analyze (synchronous for small files)
GUIDELINES_PDF_PATH = "India_Hospital_Billing_Guidelines_2025.pdf"  # your uploaded guidelines file

@app.route('/api/files/upload-and-analyze', methods=['POST'])
@jwt_required()
def upload_and_analyze():
    """
    Accept multipart/form-data:
      - file (required): PDF or image (png/jpg/jpeg/tiff)
      - force_ocr (optional): 'true'|'false' - if true, force OCR even for digital PDFs

    Returns: JSON report (see schema in docs). Always returns JSON; internal problems are reported
    inside 'meta.internal_errors' instead of raising.
    """
    result_meta_errors = []
    start_ts = datetime.now(timezone.utc)

    # The full upload-and-analyze pipeline requires additional helpers and
    # models which are not part of this starter template. Return a clear
    # Not Implemented response so callers (and smoke tests) get a stable result
    # rather than causing server-side NameErrors.
    try:
        # 1) Basic validation
        if 'file' not in request.files:
            return jsonify({'msg': "missing file field 'file'"}), 400
        f = request.files['file']
        if f.filename == '':
            return jsonify({'msg': 'no selected file'}), 400
        if not allowed_file(f.filename):
            return jsonify({'msg': f'file type not allowed. Allowed: {ALLOWED_EXT}'}), 400

        force_ocr_flag = (request.form.get('force_ocr') or 'false').lower() == 'true'

        # 2) Save file to uploads dir (unique name)
        orig_name, saved_path = save_file_storage(f)
        size = os.path.getsize(saved_path)

        # 3) Create FileRecord DB row
        fid = make_uuid("file")
        file_rec = FileRecord(
            id=fid,
            filename=orig_name,
            storage_path=saved_path,
            uploaded_at=datetime.now(timezone.utc),
            status="processing",
            size=size
        )
        db.session.add(file_rec)
        db.session.commit()

        # 4) Try to extract using pdfplumber tables first (if PDF), else OCR
        modules = try_imports()
        raw_text = ""
        notes = []
        used_pdfplumber = False
        try:
            if saved_path.lower().endswith(".pdf") and modules.get("pdfplumber"):
                items_from_tables, text_from_tables, tables_data = extract_tables_with_pdfplumber(saved_path, modules)
                if text_from_tables and len(text_from_tables.strip()) > 20 and not force_ocr_flag:
                    raw_text = text_from_tables
                    line_items = items_from_tables if items_from_tables else enhanced_line_item_parser(raw_text, tables_data)
                    used_pdfplumber = True
                    notes.append("pdfplumber used for selectable text/tables")
                else:
                    # fallback to OCR
                    raw_text = perform_ocr(saved_path, modules)
                    line_items = items_from_tables if items_from_tables else enhanced_line_item_parser(raw_text, tables_data if 'tables_data' in locals() else [])
                    notes.append("pdfplumber insufficient; OCR used")
            else:
                # not a pdf or pdfplumber not available -> OCR
                raw_text = perform_ocr(saved_path, modules)
                line_items = enhanced_line_item_parser(raw_text, [])
                notes.append("ocr used")
        except Exception as e:
            # fallback: try OCR robustly
            try:
                raw_text = perform_ocr(saved_path, modules)
                tables_data = [] if 'tables_data' not in locals() else tables_data
                line_items = enhanced_line_item_parser(raw_text, tables_data)
                notes.append("fallback-ocr used after exception")
            except Exception as e2:
                # fatal to extraction: mark file error and return
                file_rec.status = "error"
                file_rec.error = f"Extraction failed: {str(e2)}"
                db.session.commit()
                return jsonify({
                    "msg": "error during extraction",
                    "meta": {"internal_error": str(e2)}
                }), 500

        # 5) Build structured JSON (line items + meta guesses)
        # Use enhanced extraction functions
        patient_info = extract_patient_info(raw_text)
        hospital_info = extract_hospital_info(raw_text)
        dates = extract_dates_enhanced(raw_text)
        
        meta_guess = {
            "detected_patient_name": patient_info.get("patient_name"),
            "detected_patient_id": patient_info.get("patient_id"),
            "detected_age": patient_info.get("age"),
            "detected_gender": patient_info.get("gender"),
            "detected_dates": dates,
            "detected_hospital": hospital_info.get("hospital_name"),
            "detected_gst_number": hospital_info.get("gst_number"),
            "detected_address": hospital_info.get("address")
        }

        # 6) Persist ExtractedDocument
        ex_id = make_uuid("ex")
        structured_data = {"line_items": line_items, "meta": meta_guess}
        ext_doc = ExtractedDocument(
            id=ex_id,
            file_id=file_rec.id,
            raw_text=raw_text,
            structured_json=json.dumps(structured_data),  # Convert dict to JSON string
            confidence=0.6,
            processed_at=datetime.now(timezone.utc)
        )
        db.session.add(ext_doc)
        file_rec.extracted = ext_doc
        file_rec.status = "done"
        db.session.commit()

        # 7) Run validation rules (this will create ValidationFlag rows)
        try:
            run_validation_rules(db.session, ext_doc)
            notes.append("validation rules executed")
        except Exception as vr_exc:
            # non-fatal; capture
            result_meta_errors.append(f"validation_error: {str(vr_exc)}")

        # 8) Run the guidelines analyzer safely (this function returns dict and never raises)
        try:
            analysis = analyze_extracted_text_against_guidelines(raw_text, guidelines_path=GUIDELINES_PDF_PATH)
        except Exception as ae:
            analysis = {"meta": {"internal_error": f"analyzer crashed: {str(ae)}"}}
            result_meta_errors.append(str(ae))

        # 9) Generate PDF/HTML report (best-effort)
        report_path = None
        try:
            rp = generate_report(db.session, ext_doc)
            report_path = rp
            notes.append("report generated")
        except Exception as gr_exc:
            # non-fatal; attach note
            result_meta_errors.append(f"report_generation_error: {str(gr_exc)}")

        # 10) Build final JSON result (the "report")
        # Collect flags
        flags_q = ValidationFlag.query.filter(ValidationFlag.extracted_document_id == ext_doc.id).all()
        flags_out = []
        for f in flags_q:
            flags_out.append({
                "id": f.id,
                "rule": f.rule_name,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "created_at": f.created_at.isoformat()
            })

        # Enhanced confidence scoring
        # OCR confidence based on method used
        ocr_conf = 0.7 if "ocr used" in notes or "fallback-ocr used after exception" in notes else 0.9
        
        # Extraction confidence based on data completeness
        extraction_factors = {
            "has_text": 0.2 if raw_text and len(raw_text.strip()) > 50 else 0.0,
            "has_line_items": 0.2 if line_items and len(line_items) > 0 else 0.0,
            "has_patient_info": 0.15 if meta_guess.get("detected_patient_name") else 0.0,
            "has_dates": 0.15 if meta_guess.get("detected_dates", {}).get("admission") or meta_guess.get("detected_dates", {}).get("discharge") else 0.0,
            "has_hospital": 0.1 if meta_guess.get("detected_hospital") else 0.0,
            "has_totals": 0.2 if re.search(r'(?:total|grand\s+total).*?[\d,]+\.?\d*', raw_text, re.IGNORECASE) else 0.0
        }
        extraction_conf = sum(extraction_factors.values())
        extraction_conf = max(0.3, min(1.0, extraction_conf))  # Clamp between 0.3 and 1.0
        
        # Update confidence in database
        ext_doc.confidence = extraction_conf
        db.session.commit()
        
        # Overall confidence: weighted average
        overall_conf = round((ocr_conf * 0.4 + extraction_conf * 0.6), 2)

        response = {
            "file_id": file_rec.id,
            "extracted_id": ext_doc.id,
            "file": {
                "filename": file_rec.filename,
                "storage_path": file_rec.storage_path,
                "uploaded_at": file_rec.uploaded_at.isoformat(),
                "size": file_rec.size
            },
            "raw_text": raw_text,
            "structured": json.loads(ext_doc.structured_json) if ext_doc.structured_json else {},
            "validation": {
                "flags": flags_out,
                "summary": analysis.get("summary") if isinstance(analysis, dict) else {}
            },
            "analysis_details": analysis,
            "confidence_scores": {
                "ocr_confidence": round(ocr_conf, 2),
                "extraction_confidence": round(extraction_conf, 2),
                "overall_confidence": overall_conf
            },
            "report": {
                "report_path": report_path,
                "report_type": "pdf" if report_path and report_path.endswith(".pdf") else "html" if report_path else None
            },
            "meta": {
                "guidelines_path": GUIDELINES_PDF_PATH,
                "processing_time_seconds": (datetime.now(timezone.utc) - start_ts).total_seconds(),
                "notes": notes,
                "internal_errors": result_meta_errors
            }
        }

        return jsonify(response), 200

    except Exception as e:
        # last-resort defensive catch; never crash the server on user input
        tb = traceback.format_exc()
        return jsonify({
            "msg": "unexpected server error during upload-and-analyze",
            "meta": {"internal_error": str(e), "traceback": tb}
        }), 500


# -----------------------------
# Error handlers
# -----------------------------
@app.errorhandler(404)
def not_found(e):
	return jsonify({'msg': 'resource not found'}), 404


@app.errorhandler(500)
def server_error(e):
	return jsonify({'msg': 'internal server error'}), 500


if __name__ == '__main__':
	# Ensure DB tables exist (creates sqlite file if needed). In production,
	# use migrations (Flask-Migrate / Alembic) instead of create_all().
	with app.app_context():
		db.create_all()

	# Run development server. For production use a WSGI server.
	app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)


