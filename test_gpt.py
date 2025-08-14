import openai
import os

openai.api_key = "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"

response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a medical scribe."},
        {"role": "user", "content": "The patient is a 27-year-old male with sore throat and fever for 3 days. Please create a SOAP note."}
    ],
    temperature=0.3,
)

print(response.choices[0].message.content)

