VENV_NAME = env
PYTHON = python3
ACTIVATE = source $(VENV_NAME)/bin/activate

.PHONY: all init run clean test

all: init run

init:
	$(PYTHON) -m venv $(VENV_NAME)
	$(ACTIVATE) && pip install -U pip && pip install -r requirements.txt

run:
	$(ACTIVATE) && FLASK_APP=server.py FLASK_ENV=development flask run --port=8080

test:
	$(ACTIVATE) && python -m unittest discover -s tests -p "*.py"

clean:
	rm -rf $(VENV_NAME) __pycache__ *.pyc
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
