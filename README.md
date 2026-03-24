# Website Vulnerability Scanning Tool

This project at its early stage is a reconnaissance tool for pen-testers and `tech-hobbyist`.

## Requirements for the system

### Functional Requirements
Crawls webpages using provided url links
When a link accepts parameters it injects payloads to check for vulnerabilties.
Cross-site Scripting and Sql injections are performed to find vulnerabilities in system logic and string format
System also checks for Headers used and Headers omitted in system and judges to see if site is secured based on the headers used


### Non Functional Requirements
System using asynchronous calls to avoid any errors caused by delays
System uses Depth-first search algorithm to traverse through the links/pages without overlooking any hidden links
System uses depth limits to avoid bans

## How To Run

__Using Docker__
- To build: 
    ```bash
    docker-compose build
    ```
- To run docker with all dependencies
    ```bash
    docker-compose up
    ```

__Running Without Docker__
python env : 3.13.7v
- To build:
    ```bash
    pip install -r requirements.txt
    ```
`* Please be advised, it will be best to create an environment before using or performing any installations`

To create an environment on windows
Press `ctrl + shift + P`
Type `Select interpreter`
Select `Create Virtual Environment...`
Select `Venv`
Select a version to create your environment in, Remeber `3.13.7v`
If you don't have it you can download it at https://www.python.org/downloads/windows

* Do the same if you are using macOS except you'd have to change 'windows' to 'macOS'

