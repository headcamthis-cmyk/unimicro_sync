# Uni Micro V3 XML Receiver

This Flask app receives XML POST requests from Uni Micro V3.

## Security
- Basic Auth: Username and password match Uni Micro's configuration.

## Usage
- Endpoint: `/product`
- Method: POST
- Content-Type: application/xml

## Deployment
Deploy to Render, or run locally via:

```
pip install -r requirements.txt
python app.py
```