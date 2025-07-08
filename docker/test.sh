#!/bin/bash

export client_filepath=""
export server_filepath=""

function usage()
{
    echo "Usage: $0 -c <client_filepath> -s <server_filepath>"
}

function file_exists()
{
    filepath=$1
    if [[ ! -f "$filepath" ]]; then
        echo "error: ${filepath} does not exist!"
        exit 1
    else
        echo "using file: ${filepath}"
    fi
}

# Check if all mandatory command line arguments are provided
if [[ $# -lt 4 ]]; then
    usage
    exit 1
fi

# Extract client and server filepaths from command line arguments
while getopts ":c:s:" opt; do
  case $opt in
    c)
        client_filepath="$OPTARG"
        file_exists $client_filepath
    ;;
    s)
        server_filepath="$OPTARG"
        file_exists $client_filepath
    ;;
    \?) 
        echo "Invalid option -$OPTARG" >&2
        usage
        exit 1
    ;;
  esac
done

# Create test environment
mkdir -p docker/test
cp $client_filepath docker/test/UAC.xml
cp $server_filepath docker/test/UAS.xml

pushd docker
docker compose --project-name sipp_test_env up -d
# Clean up test environment
popd
