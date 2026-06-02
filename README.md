# cactus-ui
User interface for the csip-aus test harness

# Local development
Create a conda/virtual environment and run `uv sync --all-extras`

ssh port forward the cactus orchestrator machine (match with CACTUS_ORCHESTRATOR_BASEURL .env)

run the server.py file to host the UI flask server on your local machine, using the real orchestrator VM

```
uv run flask -A cactus_ui.server:app run
```