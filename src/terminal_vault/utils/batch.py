import csv
import asyncio
from typing import List, Dict
from ..core.security import calculate_entropy

async def process_entry(entry: Dict) -> Dict:
    """
    Process a single entry (e.g., check entropy).
    This is an async function to demonstrate async capabilities, 
    though CPU-bound work like entropy is usually better with multiprocessing.
    For IO-bound checks (like "have I been pwned" API), async is perfect.
    """
    secret = entry.get('secret') or entry.get('note', '')
    entropy = calculate_entropy(secret)
    entry['entropy'] = entropy
    entry['strength'] = 'Strong' if entropy > 60 else 'Moderate' if entropy > 40 else 'Weak'
    return entry

async def batch_check_entries(entries: List[Dict]) -> List[Dict]:
    tasks = [process_entry(entry) for entry in entries]
    return await asyncio.gather(*tasks)

def import_csv(filepath: str) -> List[Dict]:
    entries = []
    with open(filepath, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append(row)
    return entries
