import base64
import datetime
import io

import requests
from PIL import Image


def handler(event, context):
    response = download_cat_image()
    with open("/tmp/output_image.png", "rb") as f:
        image_data = f.read()
    encoded_image = base64.b64encode(image_data).decode("utf-8")

    body = {
        "message": f"Image Processed at {datetime.datetime.now()}",
        "input": event,
        "image": encoded_image,
    }
    response = {
        "statusCode": 200,
        "body": body,
        "headers": {"Content-Type": "application/json"},
    }
    return response


def download_cat_image():
    try:
        response = requests.get("https://cataas.com/cat")  # Unrated service
        response.raise_for_status()

        image = Image.open(io.BytesIO(response.content))
        grayscale_image = image.convert("L")

        output_buffer = io.BytesIO()
        grayscale_image.save(output_buffer, format="PNG")

        with open("/tmp/output_image.png", "wb") as f:
            f.write(output_buffer.getvalue())

        return output_buffer.getvalue()
    except requests.exceptions.HTTPError as err:
        raise Exception(f"HTTP error occurred: {err}")
    except requests.exceptions.RequestException as err:
        raise Exception(f"Request error occurred: {err}")
    except Exception as err:
        raise Exception(f"An unexpected error occurred: {err}")
