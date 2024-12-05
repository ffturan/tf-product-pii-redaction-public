import boto3
import os
import io
import json
import urllib.parse
import tempfile
import logging
import re
from pdf2image import convert_from_bytes
from pypdf import PdfWriter, PdfReader
from PIL import Image, ImageDraw  # Changed from ImageFilter to ImageDraw

#
# ENABLE LOGGING
#
logger = logging.getLogger()
logger.setLevel(logging.INFO)

#
# REQUIRED 4 POPPLER
#
if os.path.exists('/opt/bin/pdftoppm'):
    os.environ['PATH'] = f"/opt/bin:{os.environ['PATH']}"
    os.environ['LD_LIBRARY_PATH'] = f"/opt/lib:{os.environ.get('LD_LIBRARY_PATH', '')}"

#
# SET BOTO3 WORKERS
#
s3_worker = boto3.client('s3')
textract_worker = boto3.client('textract')
sns_worker = boto3.client('sns')

#
# SET ENVIRONMENT VARIABLES
#
s3_source_bucket = os.environ.get('PII_REDACT_SOURCE_BUCKET')
s3_destination_bucket = os.environ.get('PII_REDACT_DESTINATION_BUCKET')
sns_topic_arn = os.environ['SNS_TOPIC_ARN']

def detect_ssn(text):

    # Make the pattern more strict about boundaries
    #ssn_pattern = r'\b[A-Za-z]{2}(?:[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{4})\b'

    # Make separators independent
    #ssn_pattern = r'\b[A-Za-z]{2}[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'

    # Add a positive lookahead to ensure all components are present
    ssn_pattern = r'\b[A-Za-z]{2}(?=[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{4}\b)[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'

    """
    Detect Social Security Numbers using regular expressions.
    """
    # ssn_pattern = r'\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-\s]?)(?!00)\d{2}\3(?!0000)\d{4}\b'
    # ssn_pattern = r'\b(?:[A-Za-z]{2}[-\s]?)?(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-\s]?)(?!00)\d{2}\3(?!0000)\d{4}\b'
    # ssn_pattern = r'\b(?:[A-Za-z]{2}[-\s]?)?(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-\s]?)(?!00)\d{2}(?:[-\s]?)(?!0000)\d{4}\b'

    
    matches = []
    for match in re.finditer(ssn_pattern, text):
        matches.append({
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 1.0,
            'Type': 'SSN'
        })
    return {'Entities': matches}

def check_pdf_validity(pdf_bytes):
    """Check if the PDF is valid and contains pages"""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        if len(reader.pages) == 0:
            return False
        return True
    except Exception as e:
        logger.error(f"PDF validation error: {str(e)}")
        return False

#
# SNS FUNC
#
def sns_publish(sns_message):
    """Publish a message to the SNS topic"""
    try:
        sns_worker.publish(
            TopicArn=sns_topic_arn,
            Message=sns_message,
            Subject='SSN Found on Document!'
        )
    except Exception as e:
        logger.error(f"Error publishing to SNS: {e}")

#
# BLUR FUNC
#
def redact_region(image, bbox):
    """Apply black rectangle to a specific region of the image"""
    draw = ImageDraw.Draw(image)
    x1, y1, x2, y2 = [int(coord) for coord in bbox]
    draw.rectangle([x1, y1, x2, y2], fill='black')
    return image

def process_single_image(image):
    """Process a single image and redact PII regions"""
    try:
        # Convert PIL Image to bytes for Textract
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()

        if not img_byte_arr:
            raise ValueError("Failed to convert image to bytes")

        # Extract text using Textract
        textract_response = textract_worker.detect_document_text(
            Document={'Bytes': img_byte_arr}
        )

        # Create a mapping of words to their bounding boxes
        word_to_geometry = {}
        full_text = []
        text_start_index = 0

        for block in textract_response['Blocks']:
            if block['BlockType'] == 'WORD':
                word_text = block['Text']
                geometry = block['Geometry']['BoundingBox']
                
                word_to_geometry[text_start_index] = {
                    'text': word_text,
                    'geometry': {
                        'left': geometry['Left'] * image.width,
                        'top': geometry['Top'] * image.height,
                        'width': geometry['Width'] * image.width,
                        'height': geometry['Height'] * image.height
                    }
                }
                
                full_text.append(word_text)
                text_start_index += len(word_text) + 1

        full_text = ' '.join(full_text)
        
        if not full_text:
            logger.warning("No text detected in image")
            return image, {'Entities': []}

        # Detect SSNs using regex instead of Comprehend
        pii_response = detect_ssn(full_text)

        # Process each detected SSN and redact the corresponding region
        for entity in pii_response['Entities']:
            begin_offset = entity['BeginOffset']
            
            for start_index, word_data in word_to_geometry.items():
                word_end_index = start_index + len(word_data['text'])
                
                if start_index <= begin_offset < word_end_index:
                    geometry = word_data['geometry']
                    x1 = geometry['left']
                    y1 = geometry['top']
                    x2 = x1 + geometry['width']
                    y2 = y1 + geometry['height']
                    image = redact_region(image, (x1, y1, x2, y2))

        return image, pii_response, textract_response

    except Exception as e:
        logger.error(f"Error in process_single_image: {str(e)}")
        raise

#
# COMPRESS PDF FUNC
#
def compress_pdf(pdf_bytes):
    """Compress PDF using PyPDF"""
    try:
        input_pdf = io.BytesIO(pdf_bytes)
        output_pdf = io.BytesIO()
        
        reader = PdfReader(input_pdf)
        writer = PdfWriter()
        
        for page in reader.pages:
            writer.add_page(page)
        
        # Set compression parameters
        writer.add_metadata(reader.metadata)
        for page in writer.pages:
            # Compress any form XObjects
            for obj in page.get_object().get("/Resources", {}).get("/XObject", {}):
                if hasattr(obj, "compress_content_streams"):
                    obj.compress_content_streams()
            # Compress the page content
            page.compress_content_streams()
        
        writer.write(output_pdf)
        output_pdf.seek(0)
        return output_pdf.getvalue()
    except Exception as e:
        logger.error(f"Error in compress_pdf: {str(e)}")
        raise

#
# PROCESS PDF FILE FUNC
#
def process_pdf(pdf_bytes):
    """Process all pages in the PDF"""
    try:
        logger.info("Starting PDF processing")
        logger.info(f"Original PDF size: {len(pdf_bytes)} bytes")

        with tempfile.TemporaryDirectory() as temp_dir:
            logger.info(f"Converting PDF to images in {temp_dir}")
            images = convert_from_bytes(pdf_bytes, dpi=300, output_folder=temp_dir)
            
            if not images:
                raise ValueError("No images were extracted from the PDF")
            
            processed_images = []
            all_pii_responses = []
            all_text_responses = []
            
            for i, image in enumerate(images):
                logger.info(f"Processing page {i+1}")
                processed_image, pii_response, text_response = process_single_image(image)
                processed_images.append(processed_image)
                all_pii_responses.append(pii_response)
                all_text_responses.append(text_response)
            
            output_pdf = io.BytesIO()
            
            for i, img in enumerate(processed_images):
                logger.info(f"Converting processed image {i+1} to PDF")
                temp_buffer = io.BytesIO()
                img.save(temp_buffer, format='PDF', resolution=300.0)
                temp_buffer.seek(0)
                
                if output_pdf.tell() == 0:
                    img.save(output_pdf, format='PDF', resolution=300.0)
                else:
                    existing_pdf = PdfReader(output_pdf)
                    new_page_pdf = PdfReader(temp_buffer)
                    writer = PdfWriter()
                    
                    for page in existing_pdf.pages:
                        writer.add_page(page)
                    
                    writer.add_page(new_page_pdf.pages[0])
                    
                    output_pdf.seek(0)
                    output_pdf.truncate()
                    writer.write(output_pdf)
            
            output_pdf.seek(0)
            pdf_data = output_pdf.getvalue()
            
            if not pdf_data:
                raise ValueError("Generated PDF is empty")
            
            compressed_pdf = compress_pdf(pdf_data)
            
            if not check_pdf_validity(compressed_pdf):
                raise ValueError("Generated PDF is invalid or corrupted")
                
            logger.info(f"Final PDF size: {len(compressed_pdf)} bytes")
            logger.info(f"Number of pages processed: {len(processed_images)}")
            
            return compressed_pdf, all_pii_responses, all_text_responses

    except Exception as e:
        logger.error(f"Error in process_pdf: {str(e)}")
        raise

#
# MAIN FUNC
#
def lambda_handler(event, context):
    try:
        # Get bucket and key from the S3 event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])
        logger.info(f"Processing PDF: {key}")
        
        # Download the PDF from S3
        response = s3_worker.get_object(Bucket=bucket, Key=key)
        pdf_bytes = response['Body'].read()
        
        # Validate input PDF
        if not check_pdf_validity(pdf_bytes):
            raise ValueError("Input PDF is invalid or corrupted")
        
        # Process the PDF
        processed_pdf, pii_detected , text_detected = process_pdf(pdf_bytes)
        
        if processed_pdf is None:
            raise ValueError("PDF processing resulted in None output")

        # Upload the processed PDF back to S3
        output_key = f"documents/{key}"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=output_key,
            Body=processed_pdf,
            ContentType='application/pdf',
            ContentDisposition=f'attachment; filename="{os.path.basename(key)}"'
        )

        # Upload the PII response as JSON
        json_key = f"documents/{key}_pii.json"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=json_key,
            Body=json.dumps(pii_detected, indent=2),
            ContentType='application/json'
        )

        # Upload the PII response as JSON
        json_key = f"documents/{key}_textract.json"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=json_key,
            Body=json.dumps(text_detected, indent=2),
            ContentType='application/json'
        )

        # Check if SSN was found and notify
        if "SSN" in str(pii_detected):
            sns_publish(f"SSN Found on Document: {key}")
        
        logger.info(f"Processed PDF successfully uploaded to: {output_key}")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'PDF processed successfully',
                'output_key': output_key,
                'pii_detection_results': json_key
            })
        }
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        raise