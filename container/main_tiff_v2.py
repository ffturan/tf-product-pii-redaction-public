import boto3
import os
from PIL import Image, ImageFilter
import io
import json
import urllib.parse
import logging

#
# ENABLE DEBUG IF NEEDED
#

# logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)

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
redaction_confidence_score = float(os.environ.get('PII_REDACT_CONFIDENCE_SCORE', 0.8))
sns_topic_arn = os.environ['SNS_TOPIC_ARN']

def blur_region(image, bbox):
    """Apply blur to a specific region of the image"""
    x1, y1, x2, y2 = [int(coord) for coord in bbox]
    region = image.crop((x1, y1, x2, y2))
    blur_radius = 3  # Smaller radius for better results with binary/grayscale
    blurred_region = region.filter(ImageFilter.GaussianBlur(radius=blur_radius))
    image.paste(blurred_region, (x1, y1))
    return image

def process_image(image_bytes):
    """Process the image and blur PII regions"""
    image = Image.open(io.BytesIO(image_bytes))
    
    # Print image information
    print(f"Original Image Mode: {image.mode}")
    print(f"Image Size: {image.size}")
    print(f"Image Format: {image.format}")
    
    # Convert mode '1' (binary) to 'L' (grayscale) for processing
    if image.mode == '1':
        print("Converting binary image to grayscale...")
        image = image.convert('L')
        print(f"Converted Image Mode: {image.mode}")
    
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format='TIFF', compression='jpeg')
    img_byte_arr = img_byte_arr.getvalue()

    # Extract text using Textract
    textract_response = textract_worker.detect_document_text(
        Document={'Bytes': img_byte_arr}
    )

    # Create a mapping of words to their bounding boxes
    word_to_geometry = {}
    full_text = []
    text_start_index = 0

    # Process WORD blocks instead of LINE blocks
    for block in textract_response['Blocks']:
        if block['BlockType'] == 'WORD':
            word_text = block['Text']
            geometry = block['Geometry']['BoundingBox']
            
            # Store the word's position in the full text along with its geometry
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
            text_start_index += len(word_text) + 1  # +1 for the space

    # Convert list to string for Comprehend
    full_text = ' '.join(full_text)
    
    # Detect PII using Comprehend
    pii_response = comprehend_worker.detect_pii_entities(
        Text=full_text,
        LanguageCode='en'
    )

    # Process each PII entity and blur the corresponding region
    for entity in pii_response['Entities']:
        if entity['Score'] > redaction_confidence_score and entity['Type'] == 'SSN':
            begin_offset = entity['BeginOffset']
            
            # Find the word(s) that contain this PII entity
            for start_index, word_data in word_to_geometry.items():
                word_end_index = start_index + len(word_data['text'])
                
                # Check if this word contains the PII entity
                if start_index <= begin_offset < word_end_index:
                    geometry = word_data['geometry']
                    
                    # Calculate bounding box for just this word
                    x1 = geometry['left']
                    y1 = geometry['top']
                    x2 = x1 + geometry['width']
                    y2 = y1 + geometry['height']
                    
                    # Apply blur to just this word
                    image = blur_region(image, (x1, y1, x2, y2))
    
    output_buffer = io.BytesIO()
    image.save(output_buffer, format='TIFF', compression='jpeg')
    output_buffer.seek(0)
    return output_buffer.getvalue(), pii_response

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

def lambda_handler(event, context):
    try:
        # Get bucket and key from the S3 event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
        print(f"Processing image: {key}")
        
        # Download the image from S3
        response = s3_worker.get_object(Bucket=bucket, Key=key)
        image_bytes = response['Body'].read()
        
        # Print image information before processing
        with Image.open(io.BytesIO(image_bytes)) as img:
            print("=== Image Information ===")
            print(f"File: {key}")
            print(f"Mode: {img.mode}")
            print(f"Size: {img.size}")
            print(f"Format: {img.format}")
            print("=======================")
        
        # Process the image
        processed_image, pii_detected = process_image(image_bytes)
        
        # Upload the processed image back to S3
        output_key = f"documents/{key}"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=output_key,
            Body=processed_image,
            ContentType='image/tiff'
        )

        # Upload the PII response as JSON
        json_key = f"documents/{key}.json"
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
        
        print(f"Processed image successfully uploaded to: {output_key}")       
    except Exception as e:
        print(f"Error: {str(e)}")