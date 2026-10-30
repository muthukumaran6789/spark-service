const { CosmosClient } = require('@azure/cosmos');

const DATABASE_ID = process.env.COSMOS_DATABASE_ID || 'spark';
const DATABASE_THROUGHPUT = Number(process.env.COSMOS_DATABASE_THROUGHPUT || 400);

const CONTAINERS = {
  users: { id: 'Users', partitionKey: '/emailKey' },
  projects: { id: 'Projects', partitionKey: '/projectId' },
  applications: { id: 'Applications', partitionKey: '/projectId' },
  sessions: { id: 'Sessions', partitionKey: '/userId' },
};

let initialized;

function hasCosmosCredentials() {
  return Boolean(process.env.COSMOS_ENDPOINT && process.env.COSMOS_KEY);
}

async function initializeCosmos() {
  if (!hasCosmosCredentials()) {
    throw new Error('Set COSMOS_ENDPOINT and COSMOS_KEY to connect to Azure Cosmos DB.');
  }

  if (!initialized) {
    initialized = (async () => {
      const client = new CosmosClient({
        endpoint: process.env.COSMOS_ENDPOINT,
        key: process.env.COSMOS_KEY,
      });

      // Share one throughput budget across the starter containers.
      const { database } = await client.databases.createIfNotExists({
        id: DATABASE_ID,
        throughput: DATABASE_THROUGHPUT,
      });
      const containers = {};

      for (const [name, definition] of Object.entries(CONTAINERS)) {
        const { container } = await database.containers.createIfNotExists({
          id: definition.id,
          partitionKey: definition.partitionKey,
        });
        containers[name] = container;
      }

      return { client, database, containers };
    })().catch((error) => {
      initialized = undefined;
      throw error;
    });
  }

  return initialized;
}

module.exports = {
  CONTAINERS,
  DATABASE_ID,
  DATABASE_THROUGHPUT,
  hasCosmosCredentials,
  initializeCosmos,
};
