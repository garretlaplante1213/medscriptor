#!/bin/bash

# Make sure ffmpeg (if included) is in PATH
if [ -d "/home/site/wwwroot/bin" ]; then
    export PATH="/home/site/wwwroot/bin:$PATH"
fi

# Run Streamlit
streamlit run app.py --server.port 8000 --server.address 0.0.0.0
