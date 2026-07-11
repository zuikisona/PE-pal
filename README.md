have you tried analyzing an .exe but realized that PE analyzers expect you to know what 0x00400000 means...? same ;-; let's make it beginner friendly & pretty (˶ˆᗜˆ˵)

# how it works
you give PE-pal a Windows executable file. it reads the file and extracts information about its structure and what functions it uses. then it displays that info in a cute format so you don't have to stare at random hex numbers :D

## "what's inside a PE file?"
- the DOS header: the file saying "haiii, i'm an executable!" (it always starts with 4D 5A = "MZ" in text)
- sections: containers that hold code (.text), data (.data), or other stuff. each section is encrypted or not depending on how sophisticated the malware is.
- the import table (IAT): a list of functions the .exe is calling from Windows. like if it's calling CreateRemoteThread, that's sus because it lets you inject code into other processes.
- strings: readable text hidden in the binary like URLs, file paths, IPs, or registry keys. malware sometimes leaves these as clues c;
- the rich header: metadata that shows which compiler version built the file (usually hidden by malware to cover its tracks)

## "what does PE-pal do with this?"
- entropy analysis: measures how "random" each section is. normal code has patterns, encrypted/packed malware doesn't. it's a jumbled mess. (entropy > 7.0 = sus)
- classification: groups imported functions by behavior (networking, file system, process injection, etc.) so you can see what the malware is trying to do, in simple terms.
- string flagging: highlights URLs, IPs, and file paths as suspicious since badly-written malware sometimes hardcodes these
- compiler tracking: shows the compiler timeline so you can see if the file is a frankenstein of different builds

## "how does the code work?"
- you drag a file and the browser loads it into memory as bytes
web worker processes it and a separate JavaScript thread (worker.js) parses the PE structure without freezing the UI. it reads binary data using DataView API to extract all the things mentioned above.
- calculations happen. entropy is calculated for each section using information theory (frequency analysis). then, functions are categorized. strings are extracted by scanning for readable ASCII text in the hex.
- data flows back. the worker sends results to the main thread, which renders cutie charts so you can actually understand what's going on :3
- no files leave your computer! everything happens in your browser's memory. the moment you close the tab, it'll all be gone.
**tl;dr:** PE-pal is a binary file translator. it reads the instructions inside your PE file and tells you what it's trying to do in a language that doesn't require a compsci degree to understand! (´ ▽` )b

# is this a virus scanner?
no!! PE-pal is NOT a virus scanner. it will not tell you if a file is safe or not. it will only show you the internal structure of the file and highlight suspicious elements.

- a PE analyzer is designed to dissect and examine the internal structure of executable files.
- a virus scanner is designed to detect and remove malicious software.

if you want to check if a file is safe, try uploading it to [virustotal](https://www.virustotal.com/gui/home/upload).

seeing an indicator in a PE analyzer does NOT automatically mean a file is malicious! software developers often use those exact same things for legitimate reasons. finding a sus trait in an analyzer means you should take a closer look, not that it is dangerous.

# privacy policy
this runs 100% in your browser. the file never leaves your pc. you won't be uploading anything to my servers. all this magic happens locally through javascript!