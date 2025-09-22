FROM python:3.9-slim-bullseye

RUN apt-get update
RUN apt-get install -y socat

RUN pip install qiskit==2.1.1 qiskit_aer==0.17.1

# Add application
WORKDIR /challenge
COPY challenge .

# Expose the port
EXPOSE 1337

# Switch to use a non-root user from here on
USER nobody

# Start the python application
CMD ["socat", "-dd", "TCP-LISTEN:1337,reuseaddr,fork", "exec:python -u /challenge/server.py"]