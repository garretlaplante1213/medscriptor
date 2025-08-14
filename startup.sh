#!/bin/bash

# Install ffmpeg for audio processing
apt-get update && apt-get install -y ffmpeg

# Run the Streamlit app on the port provided by Azure
streamlit run scribe_app.py --server.port $PORT --server.address 0.0.0.0
