# API Documentation

Complete documentation of all API endpoints, their required inputs, and response formats.

## Base URL
```
http://localhost:5000
```

## Authentication

Most endpoints require JWT authentication. Include the token in the Authorization header:
```
Authorization: Bearer <access_token>
```

---

## Endpoints

### 1. User Registration

**Endpoint:** `POST /register`

**Authentication:** Not required

**Content-Type:** `application/json`

**Request Body (JSON):**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "securepassword123"
}
```

**Required Fields:**
- `username` (string): Unique username
- `email` (string): Valid email address
- `password` (string): Password (will be hashed)

**Response (201 Created):**
```json
{
  "msg": "user created",
  "user_id": 1,
  "username": "alice"
}
```

**Error Responses:**
- `400 Bad Request`: Missing required fields
  ```json
  {
    "msg": "username, email and password are required"
  }
  ```
- `409 Conflict`: Username or email already exists
  ```json
  {
    "msg": "username or email already exists"
  }
  ```

---

### 2. User Login

**Endpoint:** `POST /login`

**Authentication:** Not required

**Content-Type:** `application/json`

**Request Body (JSON):**
```json
{
  "username": "alice",
  "password": "securepassword123"
}
```

**Required Fields:**
- `username` (string): Registered username
- `password` (string): User's password

**Response (200 OK):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "username": "alice"
}
```

**Error Responses:**
- `400 Bad Request`: Missing credentials
  ```json
  {
    "msg": "username and password required"
  }
  ```
- `401 Unauthorized`: Invalid credentials
  ```json
  {
    "msg": "invalid credentials"
  }
  ```

---

### 3. Get User Profile

**Endpoint:** `GET /profile`

**Authentication:** Required (JWT token)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:** None (GET request)

**Response (200 OK):**
```json
{
  "profile": {
    "user_id": 1,
    "username": "alice",
    "email": "alice@example.com"
  }
}
```

**Error Responses:**
- `400 Bad Request`: Invalid token identity
  ```json
  {
    "msg": "invalid token identity"
  }
  ```
- `404 Not Found`: User not found
  ```json
  {
    "msg": "user not found"
  }
  ```

---

### 4. OCR Text Extraction

**Endpoint:** `POST /ocr`

**Authentication:** Required (JWT token)

**Content-Type:** `multipart/form-data`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**
- `files[]` (file, required): One or more files to process
  - Supported formats: PDF, PNG, JPG, JPEG, TIFF, TIF, BMP, GIF
  - Can upload multiple files in one request

**Example using curl:**
```bash
curl -X POST http://localhost:5000/ocr \
  -H "Authorization: Bearer <token>" \
  -F "files[]=@bill.pdf" \
  -F "files[]=@image.png"
```

**Response (200 OK):**
```json
{
  "results": [
    {
      "filename": "bill.pdf",
      "page_number": 1,
      "text": "Extracted text content from the PDF..."
    },
    {
      "filename": "image.png",
      "text": "Extracted text from the image..."
    }
  ]
}
```

**Error Responses:**
- `400 Bad Request`: Invalid token identity
  ```json
  {
    "msg": "invalid token identity"
  }
  ```
- `404 Not Found`: User not found
  ```json
  {
    "msg": "user not found"
  }
  ```
- `501 Not Implemented`: Missing dependencies
  ```json
  {
    "msg": "Pillow library not available"
  }
  ```
  or
  ```json
  {
    "msg": "pytesseract not available for OCR"
  }
  ```
- `500 Internal Server Error`: OCR processing error
  ```json
  {
    "msg": "error during OCR",
    "error": "Error message details"
  }
  ```

**Note:** For PDF OCR, Poppler must be installed. For image OCR, Tesseract must be installed.

---

### 5. Upload and Analyze Medical Bill

**Endpoint:** `POST /api/files/upload-and-analyze`

**Authentication:** Required (JWT token)

**Content-Type:** `multipart/form-data`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**
- `file` (file, required): Single file to upload and analyze
  - Supported formats: PDF, PNG, JPG, JPEG, TIFF, TIF, BMP, GIF
- `force_ocr` (string, optional): Force OCR even for digital PDFs
  - Values: `"true"` or `"false"` (default: `"false"`)

**Example using curl:**
```bash
curl -X POST http://localhost:5000/api/files/upload-and-analyze \
  -H "Authorization: Bearer <token>" \
  -F "file=@medical_bill.pdf" \
  -F "force_ocr=false"
```

**Response (200 OK):**
```json
{
  "file_id": "file-c082d15f-83f2-451c-b18d-23a06abd0e27",
  "extracted_id": "ex-708cfd90-e08c-4fd2-992d-f08a891fab53",
  "file": {
    "filename": "medical_bill.pdf",
    "storage_path": "/path/to/stored/file.pdf",
    "uploaded_at": "2025-11-21T17:42:20.908971",
    "size": 2359
  },
  "raw_text": "Full extracted text from the document...",
  "structured": {
    "line_items": [
      {
        "description": "Room Rent - Deluxe",
        "quantity": 3.0,
        "unit_price": 2000.0,
        "total": 6000.0
      },
      {
        "description": "Doctor Consultation",
        "quantity": 1.0,
        "unit_price": 4500.0,
        "total": 4500.0
      }
    ],
    "meta": {
      "detected_patient_name": "Rahul Sharma",
      "detected_patient_id": "RS-2025-0912",
      "detected_age": "45",
      "detected_gender": "M",
      "detected_dates": {
        "admission": "01/11/2025",
        "discharge": "04/11/2025"
      },
      "detected_hospital": "St. Augustine General Hospital",
      "detected_gst_number": "27AABCU9603R1ZX",
      "detected_address": "123 Health St., Medcity, State - 400001"
    }
  },
  "validation": {
    "flags": [
      {
        "id": "flag-55356181-0ad7-46d6-ae41-11c592d7ba2e",
        "rule": "missing_patient_name",
        "severity": "warning",
        "description": "Patient name not detected in document",
        "evidence": "No patient name patterns found",
        "created_at": "2025-11-21T17:42:20.935967"
      }
    ],
    "summary": {
      "compliance_score": 0.75,
      "issues_found": [],
      "recommendations": []
    }
  },
  "analysis_details": {
    "summary": {
      "compliance_score": 0.75,
      "issues_found": [],
      "recommendations": []
    },
    "details": {
      "checks": {
        "has_patient_info": true,
        "has_dates": true,
        "has_amounts": true,
        "has_line_items": true
      }
    }
  },
  "confidence_scores": {
    "ocr_confidence": 0.9,
    "extraction_confidence": 0.85,
    "overall_confidence": 0.87
  },
  "report": {
    "report_path": "/path/to/reports/report-uuid.html",
    "report_type": "html"
  },
  "meta": {
    "guidelines_path": "India_Hospital_Billing_Guidelines_2025.pdf",
    "processing_time_seconds": 0.085506,
    "notes": [
      "pdfplumber used for selectable text/tables",
      "validation rules executed",
      "report generated"
    ],
    "internal_errors": []
  }
}
```

**Error Responses:**
- `400 Bad Request`: Missing file or invalid file type
  ```json
  {
    "msg": "missing file field 'file'"
  }
  ```
  or
  ```json
  {
    "msg": "no selected file"
  }
  ```
  or
  ```json
  {
    "msg": "file type not allowed. Allowed: {'.pdf', '.png', '.jpg', ...}"
  }
  ```
- `500 Internal Server Error`: Processing error
  ```json
  {
    "msg": "error during extraction",
    "meta": {
      "internal_error": "Error details"
    }
  }
  ```
  or
  ```json
  {
    "msg": "unexpected server error during upload-and-analyze",
    "meta": {
      "internal_error": "Error message",
      "traceback": "Full traceback..."
    }
  }
  ```

---

## Core Functions (Internal)

These functions are used internally by the API endpoints. They are documented here for reference.

### make_uuid(prefix: str = "") -> str

**Purpose:** Generate unique identifiers

**Input:**
- `prefix` (string, optional): Prefix for the UUID (e.g., "file", "ex", "flag")

**Output:**
- Returns UUID string with optional prefix
- Example: `"file-876e0444-3474-431f-ae9b-08818dc34b3f"`

**Usage:**
```python
uuid = make_uuid()           # "6142bfe4-dc9d-4f9b-a9bd-a74bd22652a7"
file_id = make_uuid("file")  # "file-74ec5116-73b0-45b4-8b41-136a7391f7b5"
```

---

### save_file_storage(file) -> tuple[str, str]

**Purpose:** Save uploaded file to storage

**Input:**
- `file` (Flask file object): File from `request.files`

**Output:**
- Returns tuple: `(original_filename, saved_file_path)`
- Example: `("bill.pdf", "/path/to/uploads/uuid.pdf")`

**Usage:**
```python
orig_name, saved_path = save_file_storage(request.files['file'])
```

---

### try_imports() -> dict

**Purpose:** Detect available optional libraries

**Input:** None

**Output:**
- Returns dictionary of available modules:
  ```python
  {
    "pdfplumber": <module>,
    "pytesseract": <module>,
    "PIL": <module>,
    "pdf2image": <module>
  }
  ```

**Usage:**
```python
modules = try_imports()
if modules.get("pdfplumber"):
    # Use pdfplumber
```

---

### extract_tables_with_pdfplumber(pdf_path: str, modules: dict) -> tuple

**Purpose:** Extract tables and text from PDF

**Input:**
- `pdf_path` (string): Path to PDF file
- `modules` (dict): Dictionary from `try_imports()`

**Output:**
- Returns tuple: `(line_items_list, extracted_text, tables_list)`
  - `line_items_list`: List of dictionaries with structured data
  - `extracted_text`: Full text content
  - `tables_list`: Raw table data

**Example Output:**
```python
(
  [
    {
      "description": "Room Rent",
      "quantity": 3.0,
      "unit_price": 2000.0,
      "total": 6000.0
    }
  ],
  "Full text content...",
  [[["Header1", "Header2"], ["Data1", "Data2"]]]
)
```

---

### perform_ocr(file_path: str, modules: dict) -> str

**Purpose:** Perform OCR on image or PDF

**Input:**
- `file_path` (string): Path to image or PDF file
- `modules` (dict): Dictionary from `try_imports()`

**Output:**
- Returns extracted text as string
- Returns empty string if OCR fails or dependencies missing

**Usage:**
```python
text = perform_ocr("/path/to/image.png", modules)
```

---

### enhanced_line_item_parser(text: str, tables: list = None) -> list

**Purpose:** Extract structured line items from text and tables

**Input:**
- `text` (string): Raw extracted text
- `tables` (list, optional): List of table data from pdfplumber

**Output:**
- Returns list of dictionaries with line items:
  ```python
  [
    {
      "description": "Room Rent - Deluxe",
      "quantity": 3.0,
      "unit_price": 2000.0,
      "total": 6000.0,
      "tax": 0.0,
      "discount": 0.0
    }
  ]
  ```

**Usage:**
```python
line_items = enhanced_line_item_parser(text, tables)
```

---

### extract_patient_info(text: str) -> dict

**Purpose:** Extract patient information from text

**Input:**
- `text` (string): Raw text to search

**Output:**
- Returns dictionary:
  ```python
  {
    "patient_name": "Rahul Sharma",
    "patient_id": "RS-2025-0912",
    "age": "45",
    "gender": "M"
  }
  ```

**Usage:**
```python
patient_info = extract_patient_info(raw_text)
```

---

### extract_hospital_info(text: str) -> dict

**Purpose:** Extract hospital/clinic information

**Input:**
- `text` (string): Raw text to search

**Output:**
- Returns dictionary:
  ```python
  {
    "hospital_name": "St. Augustine General Hospital",
    "gst_number": "27AABCU9603R1ZX",
    "address": "123 Health St., Medcity, State - 400001"
  }
  ```

**Usage:**
```python
hospital_info = extract_hospital_info(raw_text)
```

---

### extract_dates_enhanced(text: str) -> dict

**Purpose:** Extract dates with multiple format support

**Input:**
- `text` (string): Raw text to search

**Output:**
- Returns dictionary:
  ```python
  {
    "admission": "01/11/2025",
    "discharge": "04/11/2025"
  }
  ```

**Supported Formats:**
- `DD/MM/YYYY` or `DD-MM-YYYY`
- `YYYY/MM/DD` or `YYYY-MM-DD`
- `DD Month YYYY` (e.g., "01 November 2025")

**Usage:**
```python
dates = extract_dates_enhanced(raw_text)
```

---

### verify_financial_calculations(text: str, line_items: list) -> list

**Purpose:** Verify financial calculations for accuracy

**Input:**
- `text` (string): Raw text containing totals
- `line_items` (list): List of line item dictionaries

**Output:**
- Returns list of issues found:
  ```python
  [
    {
      "type": "calculation_mismatch",
      "severity": "error",
      "description": "Subtotal mismatch: Document shows 20297, calculated 20000",
      "difference": 297.0
    }
  ]
  ```

**Checks:**
- Subtotal matches sum of line items
- Grand total = subtotal + tax
- No negative amounts

**Usage:**
```python
issues = verify_financial_calculations(raw_text, line_items)
```

---

### run_validation_rules(session, ext_doc: ExtractedDocument) -> None

**Purpose:** Run validation rules and create ValidationFlag records

**Input:**
- `session` (SQLAlchemy session): Database session
- `ext_doc` (ExtractedDocument): Document to validate

**Output:**
- Creates ValidationFlag records in database
- No return value

**Validation Rules Applied:**
1. **empty_text** (error): Text too short
2. **missing_patient_name** (warning): No patient name found
3. **missing_dates** (warning): No dates found
4. **missing_totals** (warning): No totals found
5. **missing_hospital_name** (warning): No hospital name
6. **missing_bill_number** (info): No invoice number
7. **missing_gst_number** (warning): No GST number
8. **invalid_date_order** (error): Discharge before admission
9. **negative_amounts** (error): Negative values found
10. **empty_line_item_descriptions** (warning): Empty descriptions
11. **calculation_mismatch** (error): Subtotal doesn't match
12. **total_calculation_error** (error): Grand total incorrect
13. **duplicate_line_items** (warning): Duplicate items
14. **unusual_charges** (info): Very high amounts
15. **missing_tax_breakdown** (info): No tax details
16. **currency_inconsistency** (warning): Multiple currencies

**Usage:**
```python
run_validation_rules(db.session, extracted_document)
```

---

### analyze_extracted_text_against_guidelines(text: str, guidelines_path: str = None) -> dict

**Purpose:** Analyze text against billing guidelines

**Input:**
- `text` (string): Extracted text to analyze
- `guidelines_path` (string, optional): Path to guidelines PDF

**Output:**
- Returns analysis dictionary:
  ```python
  {
    "summary": {
      "compliance_score": 0.75,
      "issues_found": [],
      "recommendations": []
    },
    "details": {
      "checks": {
        "has_patient_info": true,
        "has_dates": true,
        "has_amounts": true,
        "has_line_items": true
      }
    }
  }
  ```

**Usage:**
```python
analysis = analyze_extracted_text_against_guidelines(raw_text)
```

---

### generate_report(session, ext_doc: ExtractedDocument) -> str | None

**Purpose:** Generate HTML report for extracted document

**Input:**
- `session` (SQLAlchemy session): Database session
- `ext_doc` (ExtractedDocument): Document to report on

**Output:**
- Returns path to generated HTML report file
- Returns `None` if generation fails

**Report Contents:**
- Document metadata
- Extracted information summary
- Validation flags (grouped by severity)
- Line items table
- Structured data (JSON)
- Raw text preview

**Usage:**
```python
report_path = generate_report(db.session, extracted_document)
```

---

### allowed_file(filename: str) -> bool

**Purpose:** Check if file extension is allowed

**Input:**
- `filename` (string): Filename to check

**Output:**
- Returns `True` if extension is allowed, `False` otherwise

**Allowed Extensions:**
- PDF: `.pdf`
- Images: `.png`, `.jpg`, `.jpeg`, `.tiff`, `.tif`, `.bmp`, `.gif`

**Usage:**
```python
if allowed_file("bill.pdf"):
    # Process file
```

---

## Error Handling

All endpoints return JSON error responses with appropriate HTTP status codes:

- `400 Bad Request`: Invalid input or missing required fields
- `401 Unauthorized`: Authentication required or invalid token
- `404 Not Found`: Resource not found
- `409 Conflict`: Duplicate resource (e.g., username/email exists)
- `500 Internal Server Error`: Server-side error
- `501 Not Implemented`: Missing dependencies or features

---

## Example API Workflow

### Complete Example: Upload and Analyze a Medical Bill

**Step 1: Register User**
```bash
POST /register
Content-Type: application/json

{
  "username": "doctor",
  "email": "doctor@hospital.com",
  "password": "securepass123"
}
```

**Step 2: Login**
```bash
POST /login
Content-Type: application/json

{
  "username": "doctor",
  "password": "securepass123"
}

Response:
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "username": "doctor"
}
```

**Step 3: Upload and Analyze**
```bash
POST /api/files/upload-and-analyze
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
Content-Type: multipart/form-data

file: [binary file data]
force_ocr: false

Response: [See full response format above]
```

---

## Testing

Use the provided test scripts:
- `tests/test_upload.py` - Test upload-and-analyze endpoint
- `tests/test_ocr.py` - Test OCR endpoint
- `tests/smoke_test.py` - Basic authentication test
- `test_functions.py` - Test individual functions

---

## Notes

1. **JWT Tokens**: Tokens expire after 1 hour (configurable)
2. **File Size Limit**: Default 8MB (configurable via `MAX_CONTENT_LENGTH`)
3. **Database**: SQLite by default, can be changed via `DATABASE_URL`
4. **Dependencies**: Some features require system-level installations (Tesseract, Poppler)
5. **Reports**: Generated HTML reports are saved in `reports/` directory
6. **Uploads**: Files are saved in `uploads/` directory with unique names

