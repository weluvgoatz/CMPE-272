# CMPE-272

This project is run in WSL using Ubuntu.

# Training Model - HGB

Paste the 5 CSVs from the CIC IDS 2017 Dataset (Engelen et al's fix) into a `fixed_data/` directory alongside `src/`.

Make sure you have `sklearn`, `jupyter` and `imblearn` installed in your current environment.

Install `requirements.txt` by running `pip install -r requirements.txt` and run `src/model.ipynb` in Jupyter (Run `jupyter lab` and follow the instructions).

# Docker setup

`docker compose up --build -d victim client monitor attacker`

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

Run this while the python script is running:

`tcpdump -i eth0 -s 0 -w /captures/attacker_traffic.pcap` 

# Model predictions

First, you may want to reorder the pcap files:

`sudo reordercap attacker_traffic.pcap attacker_traffic_order.pcap`

`sudo reordercap benign_traffic.pcap benign_traffic_order.pcap`

Now you'll have a `/captures/` directory with attacker_traffic.pcap and benign_traffic.pcap. Run the fixed CICFlowMeter (Engelen et al's fix) on this directory.

Copy the produced CSVs to the `/data/` directory.

Finally, run `new_predict.py`. It'll have a mid accuracy for now...

# TODO / ordering

Capture significantly more benign data from our system. Then, capture significantly more benign/attack data from our system and train the model with it.

# Other useful commands

`docker stop $(docker ps -q)` stops all Docker containers.

`docker compose ps` or `docker ps` checks the container status.

`docker stop <container_id_or_name>` stops a particular container, useful for stopping attacks.

`cicflowmeter -f captures/attacker_traffic.pcap -c attacker_flows.csv`

`./cfm captures/attacker_traffic.pcap outputs/`

`./cfm captures/benign_traffic.pcap outputs/`

`/home/weluv/CMPE-272/data/`

`editcap -A "2017-07-07 5:00:00" -B "2017-07-07 5:30:00" data/Friday-WorkingHours.pcap data/FridaySlice.pcap`

\usr\include\pcap

sudo java -Djava.library.path="\usr\include\pcap" -jar CICFlowMeterV3.jar

sudo java -Djava.library.path="\usr\lib" -jar CICFlowMeterV3.jar

find . -name "*:Zone.Identifier" -type f -delete

chmod +x gradlew

./gradlew execute

sudo reordercap attacker_traffic.pcap attacker_traffic_order.pcap
