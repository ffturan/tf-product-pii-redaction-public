import boto3
import os
import io
import json
import urllib.parse
import logging
import re
from PIL import Image, ImageDraw

#
# ENABLE LOGGING
#
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    
    # WORKS FINE
    ssn_pattern = r'(?!666|000|[9..])\d{3}-\d{2}-\d{4}|((?!666|000|[9..])\d{3}\s\d{2}\s\d{4})|(?!000|666|[9..])\d{9}'
        
    matches = []
    for match in re.finditer(ssn_pattern, text):
        matched_text = match.group()  # Get the actual matched text
        matches.append({
            'BeginOffset': match.start(),
            'EndOffset': match.end(),
            'Score': 1.0,  # Since regex is deterministic, we use 1.0 as confidence
            'Type': 'SSN',
            'Text': matched_text  # Add the matched text to the dictionary
        })
    return {'Entities': matches}

def redact_region(image, bbox):
    """Apply black rectangle to a specific region of the image"""
    draw = ImageDraw.Draw(image)
    x1, y1, x2, y2 = [int(coord) for coord in bbox]
    draw.rectangle([x1, y1, x2, y2], fill='black')
    return image

def process_image(image_bytes):
    """Process the image and redact PII regions"""
    image = Image.open(io.BytesIO(image_bytes))
    
    # Print image information
    # print(f"Original Image Mode: {image.mode}")
    # print(f"Image Size: {image.size}")
    # print(f"Image Format: {image.format}")
    # print(f"Image Mode: {image.mode}")
    
    # Convert mode '1' (binary) to 'L' (grayscale) for processing
    # if image.mode == '1':
    #     print("Converting binary image to grayscale...")
    #     image = image.convert('L')
    #     print(f"Converted Image Mode: {image.mode}")
    
    img_byte_arr = io.BytesIO()
    # image.save(img_byte_arr, format='TIFF', compression='jpeg')
    # image.save(img_byte_arr, format='TIFF', compression='group4')
    image.save(img_byte_arr, format='TIFF')
    img_byte_arr = img_byte_arr.getvalue()

    # Extract text using Textract
    textract_response = textract_worker.detect_document_text(
        Document={'Bytes': img_byte_arr}
    )

    # Check if there are any LINE or WORD blocks
    has_text = any(
        block['BlockType'] in ['LINE', 'WORD'] 
        for block in textract_response.get('Blocks', [])
    )

    # If no text is found, return the original image bytes
    if not has_text:
        logger.info("No text detected in the image. Returning original image.")
        return image_bytes, {'Entities': []}, textract_response

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

    # Convert list to string for processing
    full_text = ' '.join(full_text)

    # DEBUG
    # print(full_text)

    # If no text was found after processing blocks, return original image
    if not full_text:
        logger.info("No processable text detected in image")
        return image, {'Entities': []}, textract_response
    else:
        # Detect SSNs using regex instead of Comprehend
        pii_response = detect_ssn(full_text)

        # Process each detected SSN and redact the corresponding region
        for entity in pii_response['Entities']:
            begin_offset = entity['BeginOffset']
            
            # Find the word(s) that contain this SSN
            for start_index, word_data in word_to_geometry.items():
                word_end_index = start_index + len(word_data['text'])
                
                # Check if this word contains the SSN
                if start_index <= begin_offset < word_end_index:
                    geometry = word_data['geometry']
                    
                    # Calculate bounding box for just this word
                    x1 = geometry['left']
                    y1 = geometry['top']
                    x2 = x1 + geometry['width']
                    y2 = y1 + geometry['height']
                    
                    # Apply black rectangle to just this word
                    image = redact_region(image, (x1, y1, x2, y2))
        
        output_buffer = io.BytesIO()
        # image.save(output_buffer, format='TIFF', compression='jpeg')
        image.save(output_buffer, format='TIFF')
        output_buffer.seek(0)
        return output_buffer.getvalue(), pii_response, textract_response

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
        processed_image, pii_detected, text_detected = process_image(image_bytes)
        
        # Upload the processed image back to S3
        output_key = f"documents/{key}"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=output_key,
            Body=processed_image,
            ContentType='image/tiff'
        )

        # Upload the PII response as JSON
        json_key = f"documents/{key}_pii.json"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=json_key,
            Body=json.dumps(pii_detected, indent=2),
            ContentType='application/json'
        )

        # Upload the TEXTRACT response as JSON
        json_key = f"documents/{key}_textract.json"
        s3_worker.put_object(
            Bucket=s3_destination_bucket,
            Key=json_key,
            Body=json.dumps(text_detected, indent=2),
            ContentType='application/json'
        )

        # Check if any SSNs were detected
        if len(pii_detected['Entities']) > 0:
            sns_publish(f"SSN Found on Document : {key}")
        
        print(f"Processed image successfully uploaded to: {output_key}")       
    except Exception as e:
        print(f"Error: {str(e)}")
