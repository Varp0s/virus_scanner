# VirusTotal API

![VirusTotal API](/images/api.png)

## Description

This is a VirusTotal API to upload files and perform hash searches to get reports.

## Dependencies

The project requires the following Python packages:
- fastapi
- uvicorn
- pydantic
- Pillow
- python-multipart
- python-dotenv
- requests
- json

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Varp0s/virus_scanner
    cd virus_scanner
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    venv\Scripts\activate  # On Windows
    ```

3. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```
4. Run a FastAPI:
    ```sh
    uvicorn main:app --reload
    ```    

## Docker Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Varp0s/virus_scanner
    cd virus_scanner
    ```
2. Run docker compose:
    ```sh
    docker-compose up -d --build
    ```
3. Run a Browser:
    ```sh
    go to http://127.0.0.1:8000
    ```

## License

This project is licensed under the MIT License.