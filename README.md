# CMPE-272

This project is run in WSL using Ubuntu.

# Docker setup

`docker compose up --build -d victim client monitor attacker`

# Benign generation

First clarify that this fails, because we want the attacks containerized:

`docker compose exec attacker ping -c 2 8.8.8.8`

Then run this to confirm the attacker container works:

`docker compose exec attacker ping -c 2 victim`

Then run this to start the monitor:

`docker exec -it cmpe-272-monitor-1 bash`

Now that you should be inside the container:

`ip a`

`tcpdump -i eth0 -w /captures/benign_traffic_test.pcap`  

and then `Ctrl+C` after a couple moments. If you want to exit the monitor interface, run `Ctrl+D` instead.

# Attack generation + detection

`attacker/run_attacks.py` runs a shuffled set of attack scenarios (Port Scan via nmap,
DoS Hulk + DDoS via hping3 flood, DoS Slowhttptest via slowhttptest, SSH/FTP brute force
via hydra) against the `victim` container only. Each scenario's start/end timestamps and
attack type are appended to `logs/attack_log.csv`. It's mounted as a volume
(`./attacker:/app`), not baked into the Dockerfile, so attacks only happen when you
explicitly run:

`docker compose exec attacker python3 /app/run_attacks.py`

To run it, the `victim` and `attacker` containers both need to be up
(`docker compose up --build -d victim attacker`). No extra setup is required --
`run_attacks.py` creates `logs/` and `logs/raw/` itself if they don't exist yet.

The attack type names (`PortScan`, `DoS Hulk`, `DoS Slowhttptest`, `DDoS`, `SSH-Patator`,
`FTP-Patator`) match the `attack_map` buckets already used in `src/model.ipynb`.

Labeling captured flows with these attack windows (instead of leaving everything
`BENIGN`) is a separate follow-up step, not yet wired in.

You must stop the client container before monitoring the attack traffic:

`docker stop cmpe-272-client-1`

Run this while the python script is running:

`tcpdump -i eth0 -s 0 -w /captures/attacker_traffic_test.pcap` 

Thus, we have generated our test data.

# Potential TODO - generate lots of more data

Here, we need to keep the benign/attack generation scripts running for a long time and then feed them into fixed_data/ as a csv so that our model can be trained with them. It's important to keep the training data generated here separate from the test data generated previously.

To generate only attacks, you should probably stop the client Docker container.

# Process data

First, you may want to reorder the pcap files. Here's an example of how to do that:

`sudo reordercap attacker_traffic_test.pcap attacker_traffic_test_order.pcap`

`sudo reordercap benign_traffic_test.pcap benign_traffic_test_order.pcap`

or so...

Now you'll have a `/captures/` directory with some capture pcaps. Run the fixed CICFlowMeter (Engelen et al's fix) on this directory. Refer to that project for instructions on how to install it, but you basically enter CICFlowMeter's directory and run `./gradlew execute` (run `chmod +x gradlew` if permission is denied, and `find . -name "*:Zone.Identifier" -type f -delete` if you run into Zone Identifier issues).

Copy the produced CSVs to the `/data/` directory, if they aren't there already.

# Training Model - HGB

Paste the 5 CSVs from the CIC IDS 2017 Dataset (Engelen et al's fix) into a `fixed_data/` directory alongside `src/`.

If you have new training data generated, paste it in `scale_data` directory alongside `src/`, and separate it into attacks and benign sub folders. 

Make sure you have `sklearn`, `jupyter` and `imblearn` installed in your current environment.

Install `requirements.txt` by running `pip install -r requirements.txt` and run `src/model.ipynb` in Jupyter (Run `jupyter lab` and follow the instructions).

# Model predictions

Finally, run `new_predict.py`. It'll have a middling accuracy if you didn't inject new data into the training data, but will have almost-if-not exactly 100 if you do inject our data.

# Results

It is hard to determine the usefulness of this system, because you can have 2 results:

1) If you insert new training data alongside the CIC-IDS-2017, the model will overfit to the new data.

2) If you don't insert the new training data, the model will perform poorly due to irreconcilable differences (timeframes, packet windows, ports) between the CIC-IDS data capture and our system's data capture.

However, the first path may be the better option despite its overfitting since it learns on specific attacks that happen to our system.

# Other useful commands

`docker stop $(docker ps -q)` stops all Docker containers.

`docker compose ps` or `docker ps` checks the container status.

`docker stop <container_id_or_name>` stops a particular container, useful for stopping attacks.
