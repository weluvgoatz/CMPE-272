# CMPE-272

This project is run in WSL using Ubuntu.

# Training Model

Paste the 8 CSVs from the CIC IDS 2017 Dataset into a `data/` directory alongside `src/`.

Make sure you have `sklearn`, `jupyter` and `imblearn` installed in your current environment.

Install `requirements.txt` by running `pip install -r requirements.txt` and run `src/model.ipynb` in Jupyter (Run `jupyter lab` and follow the instructions).

# Docker setup

`docker compose up --build -d victim client`

`docker compose up --build -d monitor`

`docker compose up --build -d attacker`

# Data production

First clarify that this fails, because we want the attacks containerized:

`docker compose exec attacker ping -c 2 8.8.8.8`

Then run this to confirm the attacker container works:

`docker compose exec attacker ping -c 2 victim`

Then run this to start the monitor:

`docker exec -it cmpe-272-monitor-1 bash`

Now that you should be inside the container:

`ip a`

`tcpdump -i eth0 -w /captures/benign_traffic.pcap`  

and then `Ctrl+C` after a couple moments. If you want to exit the monitor interface, run `Ctrl+D` instead.

Then run `python sniffer.py` and when it's done the data should be available in `flows_output.csv`.

# Model predictions

Finally, run `new_predict.py`.

# TODO

1) 

Create a python script that generates synthetic attacks, and run it in the attacker Docker container with:

`docker compose exec attacker python3 /app/run_attacks.py` or whatever we want to call the script.

It's important that this is not embedded in the Dockerfile for the attacker so that we're only explicitly declaring when attacks happen.

2) 

Export the attack mappings via joblib, and apply the mappings and label encodings to new data.

Apparently, even though the model training does fit and transform, we should only do transform for the new data, to retain the integer encodings of the original.

Then we can predict and compare results as we do in the model.

# Other useful commands

`docker stop $(docker ps -q)` stops all Docker containers.

`docker compose ps` or `docker ps` checks the container status.

`docker stop <container_id_or_name>` stops a particular container, useful for stopping attacks.
