import logging
import json
import os
from scanner.manager import process_domain
from scanner.loader import DomainEntry
from scanner.dynamodb import DynamoDBManager

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB Manager (outside handler for reuse)
# Note: Environment variables must be set
try:
    dynamodb_manager = DynamoDBManager()
except Exception as e:
    logger.error(f"Failed to initialize DynamoDBManager: {e}")
    dynamodb_manager = None

def handler(event, context):
    """
    Lambda handler for SQS events.
    """
    if not dynamodb_manager:
        logger.error("DynamoDBManager not initialized. Exiting.")
        return {"statusCode": 500, "body": "Internal Server Error"}

    logger.info(f"Received event with {len(event.get('Records', []))} records")
    
    for record in event.get('Records', []):
        try:
            body = record.get('body')
            logger.info(f"Processing message body: {body}")
            
            # Parse body
            # Expecting JSON: {"domain": "example.com", "rank": 1, "tld": "com"}
            # Or just raw string: "example.com"
            try:
                domain_data = json.loads(body)
                if isinstance(domain_data, str):
                     domain_data = {"domain": domain_data}
            except json.JSONDecodeError:
                domain_data = {"domain": body}
            
            domain_name = domain_data.get("domain")
            if not domain_name:
                logger.warning(f"No domain found in record: {body}")
                continue
            
            # Create DomainEntry
            entry = DomainEntry(
                domain=domain_name,
                rank=domain_data.get("rank", 0),
                tld=domain_data.get("tld", "")
            )
            
            # Run Scan
            logger.info(f"Starting scan for {domain_name}")
            result = process_domain(entry)
            
            # Save to DynamoDB
            dynamodb_manager.save_result(result)
            
        except Exception as e:
            logger.error(f"Error processing record: {e}")
            # If we want SQS to retry, we should raise the exception.
            # For now, let's catch it to process other records in the batch.
            # But usually for SQS Lambda triggers, if one fails, the whole batch fails (or partial batch response).
            # Let's just log for now.
            
    return {"statusCode": 200, "body": "Batch processed"}
