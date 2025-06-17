#!/bin/bash

# Start proxy.py in background
python proxy.py &

# Start app.py in foreground
python app.py