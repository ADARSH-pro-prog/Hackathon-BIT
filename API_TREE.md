# API Tree Structure

Visual representation of all API endpoints and their relationships.

## Base URL
```
http://localhost:5000
```

## API Endpoints Tree

```
Medical Bill Analysis API
│
├── 🔓 Public Endpoints (No Authentication Required)
│   │
│   ├── POST /register
│   │   ├── Input: JSON
│   │   │   {
│   │   │     "username": "string",
│   │   │     "email": "string",
│   │   │     "password": "string"
│   │   │   }
│   │   ├── Output: JSON
│   │   │   {
│   │   │     "msg": "user created",
│   │   │     "user_id": int,
│   │   │     "username": "string"
│   │   │   }
│   │   └── Status: 201 Created
│   │
│   └── POST /login
│       ├── Input: JSON
│       │   {
│       │     "username": "string",
│       │     "password": "string"
│       │   }
│       ├── Output: JSON
│       │   {
│       │     "access_token": "string (JWT)",
│       │     "username": "string"
│       │   }
│       └── Status: 200 OK
│
└── 🔒 Protected Endpoints (JWT Authentication Required)
    │
    ├── GET /profile
    │   ├── Headers: Authorization: Bearer <token>
    │   ├── Input: None (GET request)
    │   ├── Output: JSON
    │   │   {
    │   │     "profile": {
    │   │       "user_id": int,
    │   │       "username": "string",
    │   │       "email": "string"
    │   │     }
    │   │   }
    │   └── Status: 200 OK
    │
    ├── POST /ocr
    │   ├── Headers: Authorization: Bearer <token>
    │   ├── Content-Type: multipart/form-data
    │   ├── Input: Form Data
    │   │   {
    │   │     "files[]": [file1, file2, ...]  // Multiple files
    │   │   }
    │   ├── Output: JSON
    │   │   {
    │   │     "results": [
    │   │       {
    │   │         "filename": "string",
    │   │         "page_number": int,  // For PDFs
    │   │         "text": "string"     // Extracted text
    │   │       }
    │   │     ]
    │   │   }
    │   └── Status: 200 OK
    │
    └── POST /api/files/upload-and-analyze
        ├── Headers: Authorization: Bearer <token>
        ├── Content-Type: multipart/form-data
        ├── Input: Form Data
        │   {
        │     "file": file,              // Single file (required)
        │     "force_ocr": "true|false"  // Optional, default: "false"
        │   }
        │
        ├── Processing Pipeline:
        │   │
        │   ├── 1. File Validation
        │   │   └── Function: allowed_file()
        │   │
        │   ├── 2. File Storage
        │   │   └── Function: save_file_storage()
        │   │
        │   ├── 3. Text Extraction
        │   │   ├── If PDF → extract_tables_with_pdfplumber()
        │   │   │   └── Uses: enhanced_line_item_parser()
        │   │   └── Else → perform_ocr()
        │   │       └── Uses: enhanced_line_item_parser()
        │   │
        │   ├── 4. Data Extraction
        │   │   ├── extract_patient_info()
        │   │   ├── extract_hospital_info()
        │   │   └── extract_dates_enhanced()
        │   │
        │   ├── 5. Database Storage
        │   │   ├── FileRecord (created)
        │   │   └── ExtractedDocument (created)
        │   │
        │   ├── 6. Validation
        │   │   └── run_validation_rules()
        │   │       ├── Creates ValidationFlag records
        │   │       └── Uses: verify_financial_calculations()
        │   │
        │   ├── 7. Guidelines Analysis
        │   │   └── analyze_extracted_text_against_guidelines()
        │   │
        │   └── 8. Report Generation
        │       └── generate_report()
        │
        ├── Output: JSON (Comprehensive Analysis)
        │   {
        │     "file_id": "string (UUID)",
        │     "extracted_id": "string (UUID)",
        │     "file": {
        │       "filename": "string",
        │       "storage_path": "string",
        │       "uploaded_at": "ISO datetime",
        │       "size": int
        │     },
        │     "raw_text": "string",
        │     "structured": {
        │       "line_items": [
        │         {
        │           "description": "string",
        │           "quantity": float,
        │           "unit_price": float,
        │           "total": float
        │         }
        │       ],
        │       "meta": {
        │         "detected_patient_name": "string",
        │         "detected_patient_id": "string",
        │         "detected_age": "string",
        │         "detected_gender": "string",
        │         "detected_dates": {
        │           "admission": "string",
        │           "discharge": "string"
        │         },
        │         "detected_hospital": "string",
        │         "detected_gst_number": "string",
        │         "detected_address": "string"
        │       }
        │     },
        │     "validation": {
        │       "flags": [
        │         {
        │           "id": "string (UUID)",
        │           "rule": "string",
        │           "severity": "error|warning|info",
        │           "description": "string",
        │           "evidence": "string",
        │           "created_at": "ISO datetime"
        │         }
        │       ],
        │       "summary": {
        │         "compliance_score": float (0.0-1.0),
        │         "issues_found": [],
        │         "recommendations": []
        │       }
        │     },
        │     "analysis_details": {
        │       "summary": {
        │         "compliance_score": float,
        │         "issues_found": [],
        │         "recommendations": []
        │       },
        │       "details": {
        │         "checks": {
        │           "has_patient_info": bool,
        │           "has_dates": bool,
        │           "has_amounts": bool,
        │           "has_line_items": bool
        │         }
        │       }
        │     },
        │     "confidence_scores": {
        │       "ocr_confidence": float (0.0-1.0),
        │       "extraction_confidence": float (0.0-1.0),
        │       "overall_confidence": float (0.0-1.0)
        │     },
        │     "report": {
        │       "report_path": "string",
        │       "report_type": "html|pdf|null"
        │     },
        │     "meta": {
        │       "guidelines_path": "string",
        │       "processing_time_seconds": float,
        │       "notes": ["string"],
        │       "internal_errors": []
        │     }
        │   }
        │
        └── Status: 200 OK
```

## Function Call Hierarchy

```
upload_and_analyze()
│
├── save_file_storage(file)
│   └── make_uuid("file")
│
├── try_imports()
│   └── Returns: {pdfplumber, pytesseract, PIL, pdf2image}
│
├── extract_tables_with_pdfplumber(pdf_path, modules)
│   ├── enhanced_line_item_parser(text, tables)
│   └── Returns: (line_items, text, tables)
│
├── perform_ocr(file_path, modules)  // Fallback
│   └── Returns: extracted_text
│
├── enhanced_line_item_parser(text, tables)
│   └── Returns: [line_item_dicts]
│
├── extract_patient_info(text)
│   └── Returns: {patient_name, patient_id, age, gender}
│
├── extract_hospital_info(text)
│   └── Returns: {hospital_name, gst_number, address}
│
├── extract_dates_enhanced(text)
│   └── Returns: {admission, discharge}
│
├── run_validation_rules(session, ext_doc)
│   ├── extract_patient_info(text)
│   ├── extract_hospital_info(text)
│   ├── extract_dates_enhanced(text)
│   ├── verify_financial_calculations(text, line_items)
│   └── Creates ValidationFlag records
│
├── verify_financial_calculations(text, line_items)
│   └── Returns: [issues_list]
│
├── analyze_extracted_text_against_guidelines(text, path)
│   └── Returns: {summary, details}
│
└── generate_report(session, ext_doc)
    └── Returns: report_file_path
```

## Database Models Tree

```
Database Schema
│
├── User
│   ├── id (Integer, PK)
│   ├── username (String, Unique)
│   ├── email (String, Unique)
│   └── password (String, Hashed)
│
├── FileRecord
│   ├── id (String UUID, PK)
│   ├── filename (String)
│   ├── storage_path (String)
│   ├── uploaded_at (DateTime)
│   ├── status (String)
│   ├── size (Integer)
│   ├── error (Text, Nullable)
│   └── ──→ ExtractedDocument (One-to-One)
│
├── ExtractedDocument
│   ├── id (String UUID, PK)
│   ├── file_id (String, FK → FileRecord.id)
│   ├── raw_text (Text)
│   ├── structured_json (Text, JSON)
│   ├── confidence (Float)
│   ├── processed_at (DateTime)
│   └── ──→ ValidationFlag (One-to-Many)
│
└── ValidationFlag
    ├── id (String UUID, PK)
    ├── extracted_document_id (String, FK → ExtractedDocument.id)
    ├── rule_name (String)
    ├── severity (String: error|warning|info)
    ├── description (Text)
    ├── evidence (Text)
    └── created_at (DateTime)
```

## Validation Rules Tree

```
Validation Rules (15 Total)
│
├── Data Completeness (7 rules)
│   ├── empty_text (error)
│   ├── missing_patient_name (warning)
│   ├── missing_dates (warning)
│   ├── missing_totals (warning)
│   ├── missing_hospital_name (warning)
│   ├── missing_bill_number (info)
│   └── missing_gst_number (warning)
│
├── Data Quality (3 rules)
│   ├── invalid_date_order (error)
│   ├── negative_amounts (error)
│   └── empty_line_item_descriptions (warning)
│
└── Financial & Business Logic (5 rules)
    ├── calculation_mismatch (error)
    ├── total_calculation_error (error)
    ├── duplicate_line_items (warning)
    ├── unusual_charges (info)
    ├── missing_tax_breakdown (info)
    └── currency_inconsistency (warning)
```

## Request Flow Diagram

```
Client Request
    │
    ├── POST /register
    │   └──→ User Model → Database → Response
    │
    ├── POST /login
    │   └──→ User Model → JWT Token → Response
    │
    ├── GET /profile
    │   └──→ JWT Verify → User Model → Response
    │
    ├── POST /ocr
    │   └──→ JWT Verify → OCR Processing → Response
    │
    └── POST /api/files/upload-and-analyze
        │
        ├── JWT Verify
        ├── File Validation
        ├── File Storage
        ├── Text Extraction
        │   ├── PDF → pdfplumber → enhanced_line_item_parser
        │   └── Image → OCR → enhanced_line_item_parser
        ├── Data Extraction
        │   ├── extract_patient_info
        │   ├── extract_hospital_info
        │   └── extract_dates_enhanced
        ├── Database Storage
        │   ├── FileRecord
        │   └── ExtractedDocument
        ├── Validation
        │   └── run_validation_rules → ValidationFlag
        ├── Analysis
        │   └── analyze_extracted_text_against_guidelines
        ├── Report Generation
        │   └── generate_report
        └── Response (JSON)
```

## Quick Reference: JSON Inputs

### 1. Register
```json
POST /register
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

### 2. Login
```json
POST /login
{
  "username": "string",
  "password": "string"
}
```

### 3. Profile
```
GET /profile
Headers: Authorization: Bearer <token>
(No JSON body)
```

### 4. OCR
```
POST /ocr
Headers: Authorization: Bearer <token>
Content-Type: multipart/form-data
Form Data:
  files[]: [file1, file2, ...]
(No JSON body - uses form-data)
```

### 5. Upload and Analyze
```
POST /api/files/upload-and-analyze
Headers: Authorization: Bearer <token>
Content-Type: multipart/form-data
Form Data:
  file: <file>
  force_ocr: "true" | "false" (optional)
(No JSON body - uses form-data)
```

## Endpoint Summary Table

| Method | Endpoint | Auth | Input Type | Output Type |
|--------|----------|------|------------|-------------|
| POST | `/register` | ❌ | JSON | JSON |
| POST | `/login` | ❌ | JSON | JSON |
| GET | `/profile` | ✅ | None | JSON |
| POST | `/ocr` | ✅ | Form-Data | JSON |
| POST | `/api/files/upload-and-analyze` | ✅ | Form-Data | JSON |

## Function Categories

### Utility Functions
- `make_uuid()` - ID generation
- `allowed_file()` - File validation
- `try_imports()` - Library detection
- `save_file_storage()` - File storage

### Extraction Functions
- `extract_tables_with_pdfplumber()` - PDF extraction
- `perform_ocr()` - OCR processing
- `enhanced_line_item_parser()` - Line item parsing
- `extract_patient_info()` - Patient data extraction
- `extract_hospital_info()` - Hospital data extraction
- `extract_dates_enhanced()` - Date extraction

### Validation Functions
- `run_validation_rules()` - Main validation orchestrator
- `verify_financial_calculations()` - Financial verification

### Analysis Functions
- `analyze_extracted_text_against_guidelines()` - Compliance analysis
- `generate_report()` - Report generation

