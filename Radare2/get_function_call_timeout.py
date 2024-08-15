import os
import re
import time
import json
import r2pipe
import logging
import argparse
from tqdm import tqdm
from multiprocessing import Process, Queue


def configure_logging(output_dir: str) -> logging.Logger:
    """Configure logging settings."""
    log_file = os.path.join(output_dir, 'extraction.log')
    logger = logging.getLogger('extraction_logger')
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(log_file)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    return logger


def extraction(input_file_path: str, output_folder: str, file_name: str, logger: logging.Logger) -> None:
    """Extract function call graph and disassembly information from a binary file."""
    r2 = None
    try:
        start_time = time.time()
        r2 = r2pipe.open(input_file_path, flags=["-2"])

        r2.cmd("aaa")  # Enhanced analysis
        functions = r2.cmd(f'agCd')

        if not functions:
            raise ValueError(f"No functions found for file: {input_file_path}")

        output_folder = os.path.join(output_folder, file_name)
        os.makedirs(output_folder, exist_ok=True)

        dot_file_path = os.path.join(output_folder, f"{file_name}.dot")
        json_file_path = os.path.join(output_folder, f"{file_name}.json")

        function_call_graph = ['digraph code {']
        functions_info = {}

        EDGE_START_IDX = 6
        EDGE_END_IDX = -2
        pattern = r'\"(0x[0-9a-fA-F]+)\" \[label=\"([^\"]+)\"\];'

        for function in functions.split('\n')[EDGE_START_IDX:EDGE_END_IDX]:
            function = re.sub(r' URL="[^"]*"', '', function)
            function = re.sub(r' \[.*color=[^\]]*\]', '', function)
            function_call_graph.append(function)

            match = re.search(pattern, function)
            if not match:
                if 'label' in function:
                    logger.warning(f"{file_name}: No match found for function: {function}")
                continue

            address, name = match.groups()
            functions_info[address] = {
                "function_name": name,
                "instructions": []
            }

            try:
                result = r2.cmd(f'pdfj @ {address}')
                if not result.strip():
                    logger.warning(f"{file_name}: Empty response for function \"{name}\" at address \"{address}\".")
                    continue

                try:
                    json_result = json.loads(result)
                except json.JSONDecodeError:
                    logger.error(f"{file_name}: JSON decoding error for address \"{address}\".")
                    json_result = {}

                instructions = json_result.get('ops', [])
                if not instructions:
                    logger.warning(f"{file_name}: No instructions found for function \"{name}\" at address \"{address}\".")
                    continue

                for inst in instructions:
                    disasm = inst.get('disasm', 'invalid')
                    functions_info[address]['instructions'].append(disasm)
            except Exception as e:
                logger.error(f"{file_name}: Error extracting instructions at \"{address}\" for function \"{name}\": {e}")
                functions_info[address]['instructions'].append(f"error")

        function_call_graph.append('}')

        with open(dot_file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(function_call_graph))

        with open(json_file_path, 'w') as f:
            json.dump(functions_info, f, indent=4)

        end_time = time.time()
        execution_time = end_time - start_time
        logger.info(f"Successfully extracted function call information for {file_name}, time: {execution_time:.2f} seconds")

    except Exception as e:
        logger.exception(f"{file_name}: An unexpected error occurred: {e}")
    finally:
        if r2:
            r2.quit()


def worker_function(queue, *args):
    """Worker function to execute extraction and store result in a queue."""
    try:
        extraction(*args)
        queue.put(True)  # Indicate completion
    except Exception as e:
        queue.put(e)  # Put the exception in the queue for handling


def parallel_process(args_list, timeout):
    """Process the extraction tasks in parallel with a timeout."""
    # Initialize tqdm progress bar
    with tqdm(total=len(args_list), desc="Processing files",unit="file") as pbar:
        for args in args_list:
            file_name = args[2]
            queue = Queue()
            process = Process(target=worker_function, args=(queue, *args))
            process.start()
            process.join(timeout)

            if process.is_alive():
                process.terminate()
                logging.getLogger('extraction_logger').error(f"Processing of {file_name} timed out after {timeout} seconds")
            else:
                result = queue.get()  # Ensure we retrieve the result if the process finished
                if isinstance(result, Exception):
                    logging.getLogger('extraction_logger').error(f"Processing of {file_name} failed with exception: {result}")
            
            pbar.update(1)  # Update progress bar


def setup_output_directory(input_dir: str) -> str:
    """Set up the output directory for storing the extracted files."""
    output_dir = f"./{os.path.basename(input_dir)}_output"
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "results"), exist_ok=True)
    return output_dir


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Extract function call graph and disassembly information from binary files.')
    parser.add_argument('-d', '--directory', type=str, required=True, help='Path to the binary directory')
    parser.add_argument('-o', '--output', type=str, help='Path to the output directory')
    parser.add_argument('-t', '--timeout', type=int, default=600, help='Timeout value in seconds (default: 600)')
    args = parser.parse_args()
    args.directory = os.path.normpath(os.path.expanduser(args.directory))
    return args


def main() -> None:
    """Main function to orchestrate the extraction process."""
    args = parse_arguments()

    input_dir = args.directory
    output_dir = args.output if args.output else setup_output_directory(input_dir)
    logger = configure_logging(output_dir)

    extraction_args = []
    for root, _, files in os.walk(input_dir):
        for file in files:
            if '.' not in file:
                input_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, input_dir)
                output_folder = os.path.normpath(os.path.join(output_dir, "results", relative_path))
                extraction_args.append((input_file_path, output_folder, file, logger))

    parallel_process(extraction_args, args.timeout)


if __name__ == "__main__":
    main()
