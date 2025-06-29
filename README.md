# Proyecto Encrypter Cowboy

This project is an encryption tool developed in Python. It is designed to be used by individuals who revisit the project periodically. Below are the commands required to execute it and perform improvement tests.

## Installation

1. Clone the repository to your local machine:

    ```
    https://github.com/Tysaic/encrypterCowboy.git
    ```

2. Navigate to the project directory:

    ```
    cd encrypter-cowboy
    ```

3. Create a virtual environment and install the dependencies:

    ```
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

## Usage

1. Run the main script to encrypt a file:

    ```
    python one_crypter.py --encrypt <file_or_folder_path>
    ```

2. To decrypt a file, use the following command:

    ```
    python one_crypter.py --decrypt <file_or_folder_path
    ```

## Testing

1. To run the unit tests, use the following command:

    ```
    python -m unittest discover tests
    ```

2. If you want to perform coverage tests, execute the following command:

    ```
    coverage run -m unittest discover tests
    coverage report -m
    ```

Remember, you can refer to additional documentation in the `docs/README.md` file.

