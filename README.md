# trace_and_deobfuscation_experiment
Experiment for a devirtualization project with a experimental and probably inefficent optimization


<h1>Devirtualization Project Experiment</h1>


This repository contains an experimental implementation of a devirtualization project tested specifically on VMProtect 3.6. The experiment includes an optimization that may not be efficient. 


The plan was implementing tracing the code using an emulator and adding them to a list and then optimizing with an optimization that can remove deadstores and detect constants (usually vm constants in the same section with vm handlers but this version doesnt have that check) using a bitset (which is probably not the most memory efficent way and its similar to taintin ) however I wasnt able to achive what was envisioned initially, and there's alot of bugs. 
However since there's a lack of resources on this topic and I've never saw anyone doing this optimization, probably because using it for only deadstore optimization is inefficent, however this project used the taint optimization for both constant propagation and deadstore. Instead of only deadstore.

It also writes the optimized code back into the binary under ".devirt3" section.


<h2>Usage</h2>
To run the project, follow these steps:

1. Clone the repository:


 ```git clone https://github.com/NaC-L/trace_and_deobfuscation_experiment.git```

2. Navigate to the project directory:


 ```cd trace_and_deobfuscation_experiment```

3. create a build folder and use cmake


 ```mkdir build & cd build & cmake .. ```

4. build it using VS

5. then execute it using


 ```TAD.exe (filename) (emulation start address) (emulation end address) (optional stack turned into pseudo-constant 0/1) ```
