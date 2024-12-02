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
# ENABLE DEBUG IF NEEDED
#

# logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)

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
redaction_confidence_score = os.environ.get('PII_REDACT_CONFIDENCE_SCORE')
sns_topic_arn = os.environ['SNS_TOPIC_ARN']

#
# SNS FUNC
# 

def sns_publish(sns_message):
    """Publish a message to the SNS topic"""
    try:
        sns_worker.publish(
            TopicArn=sns_topic_arn,
            Message=sns_message,
            Subject='SSN Found on Document !',
        )
    except Exception as e:
        print(f"Error publishing to SNS: {e}")

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
            print("Warning: No text detected in image")
            return image, {'Entities': []}

        # Detect PII using Comprehend
        pii_response = comprehend_worker.detect_pii_entities(
            Text=full_text,
            LanguageCode='en'
        )

        # Process each PII entity and blur the corresponding region
        for entity in pii_response['Entities']:
            if entity['Score'] > redaction_confidence_score and entity['Type'] == 'SSN' :
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
        print(f"Error in process_single_image: {str(e)}")
        raise

#
# COMPRESS PDF FUNC
#

def compress_pdf(pdf_bytes):
    """Compress PDF using PyPDF"""
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

#
# PROCESS PDF FILE FUNC
#

def process_pdf(pdf_bytes):
    """Process all pages in the PDF"""
    try:
        print("Starting PDF processing")
        # Convert PDF to images
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"Converting PDF to images in {temp_dir}")
            images = convert_from_bytes(pdf_bytes, dpi=200, output_folder=temp_dir)
            
            if not images:
                raise ValueError("No images were extracted from the PDF")
            
            processed_images = []
            all_pii_responses = []
            
            # Process each page
            for i, image in enumerate(images):
                print(f"Processing page {i+1}")
                processed_image, pii_response = process_single_image(image)
                processed_images.append(processed_image)
                all_pii_responses.append(pii_response)
            
            # Convert processed images back to PDF
            output_pdf = io.BytesIO()
            print("Converting processed images back to PDF")
            processed_images[0].save(
                output_pdf, 
                "PDF", 
                resolution=100.0, 
                save_all=True,
                optimize=True,
                quality=95,
                append_images=processed_images[1:]
            )
            output_pdf.seek(0)
            
            pdf_data = output_pdf.getvalue()
            if not pdf_data:
                raise ValueError("Generated PDF is empty")
            # Add final compression step
            compressed_pdf = compress_pdf(pdf_data)
                
            return compressed_pdf, all_pii_responses

    except Exception as e:
        print(f"Error in process_pdf: {str(e)}")
        raise

#
# MAIN FUNC
#

def lambda_handler(event, context):
    try:
        # Get bucket and key from the S3 event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])
        print(f"Processing PDF: {key}")
        
        # Download the PDF from S3
        response = s3_worker.get_object(Bucket=bucket, Key=key)
        pdf_bytes = response['Body'].read()
        
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
            ContentType='application/pdf'
        )

        # Upload the PII response as JSON
        json_key = f"redacted/{key}.json"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=json_key,
            Body=json.dumps(pii_detected, indent=2),
            ContentType='application/json'
        )
        # Load the JSON data into a Python dictionary
        json_data = json.loads(json.dumps(pii_detected, indent=2))

        # Check if the word SSN exists 
        if "SSN" in str(json_data):
            sns_publish(f"SSN Found on Document : {key}")
        
        print(f"Processed PDF successfully uploaded to: {output_key}")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'PDF processed successfully',
                'output_key': output_key,
                'pii_detection_results': json_key
            })
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        raise