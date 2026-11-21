import os, sys
import json


def load(path):
    with open(path) as f:
        return json.load(f)


def main():
    unused = 1
    print(load(sys.argv[1]))


if __name__ == "__main__":
    main()
