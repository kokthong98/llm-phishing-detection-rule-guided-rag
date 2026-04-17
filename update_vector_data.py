import os
import sys
import shutil
from pathlib import Path

from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

import get_key

os.environ["OPENAI_API_KEY"] = get_key.get_openai_key()
os.environ["LANGCHAIN_TRACING_V2"] = get_key.get_langchain_tracing_key()
os.environ["LANGCHAIN_API_KEY"] = get_key.get_langchain_api_key()

sys.stdout.reconfigure(encoding='utf-8')

# Absolute path to the script
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)

local_folder = "faiss_index"
faiss_path = os.path.join(script_dir, local_folder)

# Delete old FAISS folder
if os.path.exists(faiss_path):
    shutil.rmtree(faiss_path)

print("Now loading knowledge.txt and creating vector data...\n")
print("Current Working Directory:", os.getcwd())

knowledge_path = Path(script_dir) / "knowledge.txt"
print("Knowledge File Path:", knowledge_path)

# Read the full knowledge.txt
with open(knowledge_path, "r", encoding="utf-8") as f:
    full_text = f.read()

# Split by rule blocks using 'Rule ID:' as anchor
raw_blocks = full_text.split("Rule ID:")

docs = []

for block in raw_blocks:
    block = block.strip()

    # skip empty and section headers
    if not block:
        continue

    # rebuild the removed prefix
    block_text = "Rule ID: " + block

    # keep only actual rule blocks
    if "Category:" in block_text and "Rule:" in block_text:
        docs.append(Document(page_content=block_text))

print(f"Now creating rule-based document chunks...\nTotal rule chunks: {len(docs)}")

print("Now creating embeddings...\n")
embeddings = OpenAIEmbeddings()

print("Now creating vector database via FAISS...\n")
db = FAISS.from_documents(docs, embeddings)
db.save_local(faiss_path)

print("FAISS index created successfully.")
