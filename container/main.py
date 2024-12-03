import boto3
import os
import io
import json
import urllib.parse
import tempfile
import logging
from pdf2image import convert_from_bytes
from pypdf import PdfWriter, PdfReader
from PIL import Image, ImageFilter

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
comprehend_worker = boto3.client('comprehend')
sns_worker = boto3.client('sns')

#
# SET ENVIRONMENT VARIABLES
#
s3_source_bucket = os.environ.get('PII_REDACT_SOURCE_BUCKET')
s3_destination_bucket = os.environ.get('PII_REDACT_DESTINATION_BUCKET')
redaction_confidence_score = float(os.environ.get('PII_REDACT_CONFIDENCE_SCORE', 0.9))
sns_topic_arn = os.environ['SNS_TOPIC_ARN']

#
# PDF VALIDATION FUNC
#
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
def blur_region(image, bbox):
    """Apply blur to a specific region of the image"""
    x1, y1, x2, y2 = [int(coord) for coord in bbox]
    region = image.crop((x1, y1, x2, y2))
    blurred_region = region.filter(ImageFilter.GaussianBlur(radius=10))
    image.paste(blurred_region, (x1, y1))
    return image

#
# PROCESS SINGLE IMAGE FUNC
#
def process_single_image(image):
    """Process a single image and blur PII regions"""
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

        # Detect PII using Comprehend
        pii_response = comprehend_worker.detect_pii_entities(
            Text=full_text,
            LanguageCode='en'
        )

        # Process each PII entity and blur the corresponding region
        for entity in pii_response['Entities']:
            if entity['Score'] > redaction_confidence_score and entity['Type'] == 'SSN':
                begin_offset = entity['BeginOffset']
                
                for start_index, word_data in word_to_geometry.items():
                    word_end_index = start_index + len(word_data['text'])
                    
                    if start_index <= begin_offset < word_end_index:
                        geometry = word_data['geometry']
                        x1 = geometry['left']
                        y1 = geometry['top']
                        x2 = x1 + geometry['width']
                        y2 = y1 + geometry['height']
                        image = blur_region(image, (x1, y1, x2, y2))

        return image, pii_response

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

        # Convert PDF to images
        with tempfile.TemporaryDirectory() as temp_dir:
            logger.info(f"Converting PDF to images in {temp_dir}")
            images = convert_from_bytes(pdf_bytes, dpi=300, output_folder=temp_dir)
            
            if not images:
                raise ValueError("No images were extracted from the PDF")
            
            processed_images = []
            all_pii_responses = []
            
            # Process each page
            for i, image in enumerate(images):
                logger.info(f"Processing page {i+1}")
                processed_image, pii_response = process_single_image(image)
                processed_images.append(processed_image)
                all_pii_responses.append(pii_response)
            
            # Create a new PDF using PyPDF
            output_pdf = io.BytesIO()
            
            # Convert each image to PDF pages
            for i, img in enumerate(processed_images):
                logger.info(f"Converting processed image {i+1} to PDF")
                temp_buffer = io.BytesIO()
                img.save(temp_buffer, format='PDF', resolution=300.0)
                temp_buffer.seek(0)
                
                # Add the page to the final PDF
                if output_pdf.tell() == 0:  # First page
                    img.save(output_pdf, format='PDF', resolution=300.0)
                else:
                    # Append subsequent pages
                    existing_pdf = PdfReader(output_pdf)
                    new_page_pdf = PdfReader(temp_buffer)
                    writer = PdfWriter()
                    
                    # Copy existing pages
                    for page in existing_pdf.pages:
                        writer.add_page(page)
                    
                    # Add new page
                    writer.add_page(new_page_pdf.pages[0])
                    
                    # Save the combined PDF
                    output_pdf.seek(0)
                    output_pdf.truncate()
                    writer.write(output_pdf)
            
            output_pdf.seek(0)
            pdf_data = output_pdf.getvalue()
            
            if not pdf_data:
                raise ValueError("Generated PDF is empty")
            
            # Compress the final PDF
            compressed_pdf = compress_pdf(pdf_data)
            
            # Validate the final PDF
            if not check_pdf_validity(compressed_pdf):
                raise ValueError("Generated PDF is invalid or corrupted")
                
            logger.info(f"Final PDF size: {len(compressed_pdf)} bytes")
            logger.info(f"Number of pages processed: {len(processed_images)}")
            
            return compressed_pdf, all_pii_responses

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
        processed_pdf, pii_detected = process_pdf(pdf_bytes)
        
        if processed_pdf is None:
            raise ValueError("PDF processing resulted in None output")

        # Upload the processed PDF back to S3
        output_key = f"redacted/{key}"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=output_key,
            Body=processed_pdf,
            ContentType='application/pdf',
            ContentDisposition=f'attachment; filename="{os.path.basename(key)}"'
        )

        # Upload the PII response as JSON
        json_key = f"redacted/{key}.json"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=json_key,
            Body=json.dumps(pii_detected, indent=2),
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