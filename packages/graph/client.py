# packages/graph/client.py
import os

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase

load_dotenv()  # secrets via .env (CLAUDE.md) ; défauts alignés sur infra/docker


class Neo4jClient:
    _driver: Driver | None = None

    @classmethod
    def get_driver(cls) -> Driver:
        if cls._driver is None:
            uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
            user = os.getenv("NEO4J_USER", "neo4j")
            pwd = os.getenv("NEO4J_PASSWORD", "cuzpassword")
            cls._driver = GraphDatabase.driver(uri, auth=(user, pwd))
        return cls._driver

    @classmethod
    def close(cls) -> None:
        if cls._driver:
            cls._driver.close()
            cls._driver = None
