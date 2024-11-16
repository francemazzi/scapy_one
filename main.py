from fastapi import FastAPI

from packet_sniffer import PacketSniffer

app = FastAPI(
    title="Scapy test",
    description="Sniffer di pacchetti",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {"frama": "Benvenuto in scapy test ;-)"}

@app.get("/saluto/{nome}")
async def saluta(nome: str):
    return {"messaggio": f"Ciao, {nome}!"}


@app.get("/sniff")
async def sniff():
    sniffer = PacketSniffer()
    results = sniffer.sniff_packets("78.210.61.161")
    print("Connessioni attive:", results["active_connections"])
    print("\nPacchetti catturati:", results["packets"])
    return {"packet": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 