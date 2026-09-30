const axios = require('axios');
require('dotenv').config();

const key = process.env.AZURE_AI_API_KEY;
const host = 'https://av96165607-9848-resource.services.ai.azure.com';

async function listDeployments() {
  const urls = [
    `${host}/openai/deployments?api-version=2024-02-15-preview`,
    `${host}/openai/deployments?api-version=2024-10-21`,
    `${host}/openai/models?api-version=2024-02-15-preview`,
    `${host}/models?api-version=2024-05-01-preview`,
  ];

  for (const url of urls) {
    console.log(`\nGetting: ${url}`);
    try {
      const res = await axios.get(url, {
        headers: { 'api-key': key }
      });
      console.log('✅ SUCCESS!');
      console.log(JSON.stringify(res.data, null, 2));
      return;
    } catch (err) {
      console.log('Status:', err.response?.status);
      console.log('Error:', JSON.stringify(err.response?.data || err.message));
    }
  }
}

listDeployments();
