import logging
import json
import os
import csv
import boto3
from botocore.exceptions import ClientError
import itertools

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.resource('sqs')
queue_url = os.getenv("QUEUE_URL")

def handler(event, context):
    """
    Dispatcher handler.
    Input event: {"limit": 100, "offset": 0, "csv_path": "majestic_million.csv"}
    """
    limit = event.get("limit", 100)
    offset = event.get("offset", 0)
    csv_path = event.get("csv_path", "majestic_million.csv")
    
    if not queue_url:
        logger.error("QUEUE_URL environment variable not set")
        return {"statusCode": 500, "body": "QUEUE_URL not set"}
        
    queue = sqs.Queue(queue_url)
    
    logger.info(f"Dispatching {limit} domains from {csv_path} starting at {offset}")
    
    sent_count = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Skip header
            next(reader, None)
            
            # Skip offset
            # itertools.islice is efficient
            start_index = offset
            end_index = offset + limit
            
            # Create an iterator for the slice
            target_rows = itertools.islice(reader, start_index, end_index)
            
            batch = []
            for row in target_rows:
                if len(row) < 3:
                    continue
                    
                try:
                    rank = int(row[0])
                    domain = row[2]
                    tld = row[3]
                    
                    message = {
                        "rank": rank,
                        "domain": domain,
                        "tld": tld
                    }
                    
                    batch.append({
                        'Id': str(rank),
                        'MessageBody': json.dumps(message)
                    })
                    
                    if len(batch) == 10:
                        queue.send_message_batch(Entries=batch)
                        sent_count += len(batch)
                        batch = []
                        
                except ValueError:
                    continue
            
            # Send remaining
            if batch:
                queue.send_message_batch(Entries=batch)
                sent_count += len(batch)
                
    except FileNotFoundError:
        logger.error(f"CSV file not found: {csv_path}")
        return {"statusCode": 500, "body": "CSV file not found"}
    except Exception as e:
        logger.error(f"Error dispatching domains: {e}")
        return {"statusCode": 500, "body": str(e)}
        
    logger.info(f"Successfully dispatched {sent_count} domains")
    return {"statusCode": 200, "body": f"Dispatched {sent_count} domains"}
