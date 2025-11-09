# cactus-ui
User interface for the csip-aus test harness

# Local development
Create a conda/virtual environment and run pip install -e .[dev,test]

ssh port forward the cactus orchestrator machine (match with CACTUS_ORCHESTRATOR_BASEURL .env)

run the server.py file to host the UI flask server on your local machine, using the real orchestrator VM

```
flask -A cactus_ui.server:app run
```