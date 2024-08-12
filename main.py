import typer
from rich import print
import requests
import socket
from typing_extensions import Annotated
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import threading


app = typer.Typer(add_completion=False, help="URL Path find CLIs.", rich_markup_mode="markdown")


stop_event = threading.Event()


def export_list_to_csv(data: dict, file: str):
    try:
        with open(file, "w") as f:
            for item in data:
                f.write(f"{item['url']},{item['status_code']},{item['public_ip']},{item['web_tittle']}\n")
    except Exception as e:
        print(f"Error exporting data to CSV: {e}")
        return False
    return True


def check_exist_file(file: str):
    try:
        with open(file, "r") as f:
            return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print(e)
        return False


def read_file(file: str) -> list[str]:
    try:
        with open(file, 'r') as file:
            lineas = file.readlines()
            lineas_limpias = [linea.strip() for linea in lineas]
        return lineas_limpias
    except FileNotFoundError:
        print(f"File {file} not found")
        return []
    except IOError as e:
        print(f"Error reading the file {file}: {e}")
        return []


def url_to_domain(url: str):
    return url.split("/")[2]


def remove_last_slash_url(url: str):
    if url[-1] == "/":
        return url[:-1]
    return url


def get_public_ip(url: str) -> str:
    domain = url_to_domain(url)
    try:
        ip_publica = socket.gethostbyname(domain)
        return ip_publica
    except socket.gaierror:
        return ""


def web_request(url: str, path: str, timeout: int = 10) -> dict:
    url = remove_last_slash_url(url)
    full_url = f"{url}{path}"
    public_ip = get_public_ip(url)
    try:
        response = requests.get(full_url, timeout=timeout)
        return {
            "url": full_url,
            "status_code": response.status_code,
            "public_ip": public_ip,
            "web_tittle": response.text.split("<title>")[1].split("</title>")[0],
        }
    except requests.exceptions.HTTPError as e:
        return {
            "url": full_url,
            "status_code": 404,
            "public_ip": public_ip,
            "web_tittle": "",
        }
    except requests.exceptions.RequestException as e:
        return {
            "url": full_url,
            "status_code": 0,
            "public_ip": public_ip,
            "web_tittle": "",
        }
    except Exception as e:
        return {
            "url": full_url,
            "status_code": 0,
            "public_ip": public_ip,
            "web_tittle": "",
        }


@app.command()
def one(
    url: Annotated[
        str, typer.Argument(help="example: https://localhost | URL a la que se le realizará la solicitud HTTP.")
    ],
    path: Annotated[
        list[str], typer.Argument(help="example: / /api /orm | Path a añadir a la URL antes de realizar la solicitud HTTP.")
    ]
    ) -> None:
    """
    **:sparkles: Realiza una solicitud HTTP a una URL con un path especificado.**

    example: ```python main.py one https://localhost / /api /orm```
    """
    for i in path:
        result = web_request(url, i)
        print(json.dumps(result))
    return


@app.command()
def list(
    flat_file: str, 
    path: list[str], 
    export_csv: bool = False,
    ) -> None:
    """
    **:sparkles: Lee una lista de URLs desde un archivo de texto plano y realiza una solicitud HTTP a cada URL con los paths especificados.**
    Parámetros:

    * flat_file (str): Ruta del archivo que contiene las URLs. Cada línea del archivo debe ser una URL.

    * path (list[str]): Lista de paths a añadir a cada URL antes de realizar la solicitud HTTP.**

    Ejemplo:

    El archivo 'urls.txt' contiene:

    ```

    http://example.com

    http://another-example.com
    
    ```

    Y los paths especificados son

    ```

    /path1

    /path2

    ```

    El comando sería: ```python main.py list urls.txt /path1 /path2```
    """
    global stop_event
    stop_event.clear()
    data = [{"url": "URL", "status_code": "Status Code", "public_ip": "Public IP", "web_tittle": "Web Tittle"}]
    current_time = time.strftime("%Y-%m-%d-%H-%M-%S")

    if not check_exist_file(flat_file):
        print(f"File {flat_file} not found")
        return

    url_list = read_file(flat_file)

    if not len(url_list):
        print(f"File {flat_file} is empty")
        return

    def process_url(url, path):
        if stop_event.is_set():
            return None
        result = web_request(url, path)
        print(json.dumps(result))
        return result

    def signal_handler(sig, frame):
        print("Process interrupted by user. Exiting...")
        stop_event.set()

    total_operations = len(url_list) * len(path)
    count_operations = 0

    signal.signal(signal.SIGINT, signal_handler)

    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_url = {executor.submit(process_url, url, i): (url, i) for url in url_list for i in path}
            for future in as_completed(future_to_url):
                count_operations += 1
                print(f"Progress: {count_operations}/{total_operations}")
                url, i = future_to_url[future]
                if stop_event.is_set():
                    break
                try:
                    result = future.result()
                    if result:
                        data.append(result)
                except Exception as e:
                    print(f"Error processing URL {url} with path {i}: {e}")
    finally:
        if export_csv:
            export_list_to_csv(data, f"{current_time}.csv")

    return


@app.callback(invoke_without_command=True)
def default(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


if __name__ == "__main__":
    app()
