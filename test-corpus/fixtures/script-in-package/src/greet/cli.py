import argparse


def main():
    parser = argparse.ArgumentParser(description="Greet someone.")
    parser.add_argument("name")
    parser.add_argument("--shout", action="store_true")
    args = parser.parse_args()
    message = f"Hello, {args.name}!"
    print(message.upper() if args.shout else message)


if __name__ == "__main__":
    main()
