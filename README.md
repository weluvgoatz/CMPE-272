# CMPE-272

This project is run in WSL using Ubuntu.

Paste the 8 CSVs from the CIC IDS 2017 Dataset into a `data/` directory alongside `src/`.

Make sure you have `sklearn`, `jupyter` and `imblearn` installed in your current environment.

Install `requirements.txt` by running `pip install -r requirements.txt` and run `src/model.ipynb` in Jupyter (Run `jupyter lab` and follow the instructions).

Docker setup:

docker compose up --build -d victim client

docker compose up --build -d monitor

docker exec -it cmpe-272-monitor-1 bash



ip a

cicflowmeter -i eth0 -c /captures/benign_flows.csv

OR

tcpdump -i eth0 -w /captures/benign_traffic.pcap

