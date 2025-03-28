import argparse
import hashlib
import logging
import os
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Simulates a random oracle for cryptographic research and testing."
    )

    parser.add_argument(
        "-i",
        "--input",
        type=str,
        required=True,
        help="The input string to the random oracle.",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=32,
        help="The length of the output in bytes (default: 32).",
    )
    parser.add_argument(
        "-s",
        "--salt",
        type=str,
        default=None,
        help="An optional salt for the random oracle. If not provided, a random salt is generated.",
    )
    parser.add_argument(
        "-n",
        "--num_outputs",
        type=int,
        default=1,
        help="Number of outputs to generate for the same input and configuration.",
    )
    parser.add_argument(
        "-k",
        "--key",
        type=str,
        default=None,
        help="An optional key for the HMAC. If not provided HMAC will not be used.",
    )

    parser.add_argument(
        "-a",
        "--algorithm",
        type=str,
        default="SHA256",
        choices=["SHA256", "SHA384", "SHA512", "BLAKE2b"],
        help="Hash algorithm to use (default: SHA256).",
    )
    
    return parser.parse_args()


def generate_random_oracle_output(input_data, length, salt=None, algorithm="SHA256", key=None):
    """
    Generates a random output based on the input using HKDF and the specified hash algorithm.

    Args:
        input_data (str): The input string.
        length (int): The desired length of the output in bytes.
        salt (str, optional):  Salt to use. If None, a random salt will be generated.
        algorithm (str, optional): Hash algorithm to use. Defaults to "SHA256".
        key (str, optional): Key to use in HMAC.  If None, HMAC is not used

    Returns:
        bytes: The random output.
    """
    try:
        input_bytes = input_data.encode("utf-8")

        # Choose the hash algorithm
        if algorithm == "SHA256":
            hash_algorithm = hashes.SHA256()
        elif algorithm == "SHA384":
            hash_algorithm = hashes.SHA384()
        elif algorithm == "SHA512":
            hash_algorithm = hashes.SHA512()
        elif algorithm == "BLAKE2b":
            hash_algorithm = hashes.BLAKE2b(digest_size=length)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        # Generate a random salt if none is provided
        if salt is None:
            salt_bytes = os.urandom(16)  # 16 bytes is a reasonable default
            logging.info("Generated a random salt.")
        else:
            salt_bytes = salt.encode("utf-8")
            logging.info("Using provided salt.")

        if key is None:
            # Use HKDF without HMAC for basic Random Oracle implementation
            hkdf = HKDF(
                algorithm=hash_algorithm,
                length=length,
                salt=salt_bytes,
                info=b"random_oracle_output",  # Contextual information
                backend=default_backend(),
            )
            output = hkdf.derive(input_bytes)

        else:
            #Implement HKDF-HMAC
            key_bytes = key.encode('utf-8')

            # Generate HMAC
            h = hmac.HMAC(key_bytes, hash_algorithm, backend=default_backend())
            h.update(input_bytes)
            output = h.finalize()
           
            if len(output) > length:
                output = output[:length]

        return output

    except ValueError as e:
        logging.error(f"Value error: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def main():
    """
    Main function to parse arguments and generate random oracle outputs.
    """
    try:
        args = setup_argparse()

        # Input validation
        if args.length <= 0:
            raise ValueError("Output length must be positive.")

        if args.salt is not None and not isinstance(args.salt, str):
            raise ValueError("Salt must be a string.")

        if args.num_outputs <= 0:
            raise ValueError("Number of outputs must be positive.")

        logging.info(f"Generating {args.num_outputs} random oracle output(s) for input: {args.input}")
        logging.info(f"Output length: {args.length} bytes")
        logging.info(f"Salt: {'Provided' if args.salt else 'Randomly generated'}")
        logging.info(f"Hash algorithm: {args.algorithm}")
        logging.info(f"HMAC Key: {'Provided' if args.key else 'Not used'}")


        for i in range(args.num_outputs):
            output = generate_random_oracle_output(
                args.input, args.length, args.salt, args.algorithm, args.key
            )
            print(f"Output {i+1}: {output.hex()}")

    except ValueError as e:
        logging.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()