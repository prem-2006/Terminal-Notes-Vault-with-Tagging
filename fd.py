import argparse
import json
import os

# Define location of JSON file to store notes
NOTES_FILE = "fd_notes.json"

# Load existing notes if file exists, else empty list
def load_notes():
    if os.path.exists(NOTES_FILE):
        if os.path.getsize(NOTES_FILE) == 0:
            return []
        with open(NOTES_FILE, "r") as f:
            return json.load(f)
    return []


# Save notes list back to JSON file
def save_notes(notes):
    with open(NOTES_FILE, "w") as f:
        json.dump(notes, f, indent=2)


def search_notes(args):
    notes = load_notes()
    filtered_notes = [note for note in notes if note.get('tag') == args.tag]
    
    if not filtered_notes:
        print(f"No notes found with tag '{args.tag}'.")
    else:
        for idx, note in enumerate(filtered_notes, 1):
            print(f"{idx}. {note['text']} (tag: {note.get('tag', '')})")


# Add a note (from CLI argument) to JSON file
def add_note(args):
    notes = load_notes()
    notes.append({"text": args.text, "tag": args.tag})
    save_notes(notes)
    print(f'Note saved with tag: {args.tag}')


# Setup argparse for CLI command parsing
parser = argparse.ArgumentParser(description="fd notes app")
subparsers = parser.add_subparsers()

# Add command with one argument 'text' (the note content)
parser_add = subparsers.add_parser('add', help='Add a note')
parser_add.add_argument('text', type=str, help='Text of the note')
parser_add.add_argument('--tag', type=str, default="", help='Tag for the note (e.g. maths)')
parser_add.set_defaults(func=add_note)
parser_search = subparsers.add_parser('fetch', help='Search notes by tag')
parser_search.add_argument('tag', type=str, help='Tag name to filter notes')
parser_search.set_defaults(func=search_notes)
