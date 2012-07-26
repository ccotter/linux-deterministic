
#About

This directory serves as a staging ground to keep track of TODOs, bugs, .configs
for the various hosts I test my kernel on, etc. This directory really has no
place in the kernel source tree, but it is very convenient for me as I develop
this **linux-deterministic** project to keep everything here.

#My massive TODO section

In order of importance with a tag indicating priority:

* *stability* - The code exists, but is buggy.
* *feature* - Need to implement this feature.
* *low* - Need to refactor code or some other less important administrative task
(eg. conform to Documentation/CodingStyle, move code into a proper location).


##Memory bugs (stability)

The worst bug(s) that have plagued me so far have by far been memory bugs. Right
now, doing a bunch of merges (thousands or more) and continually forking off
`ps -ef` causes kernel OOPSs and kernel reboots. Some ideas and things that need
to be done:

* Retrace through all the pieces of memory I need to worry about (mmap/brk,
hugetlb, KSM, among others).
* I reused a lot of existing memory code, but that code was written assuming
execution in the context of the `current` process, not on behalf of some other
process. The most likely cause(s) of my bugs are race conditions that would
never normally happen if always executing in the context of `current`.
* Find repeatable test cases (at least ones that can easily be recreated *most*
of the time).
* Possibly, a rewrite of the current design I have for performing the three
memory operations from Bryan Ford's paper: COPY/ZERO/MERGE.
* Another possibility is a redesign of how I even approach implementing the
three memory operations.
   * Some sort of remote procedure call where the actual process whose memory
   I want to change batches operations and performs them when `current` is the
   running context (see http://stackoverflow.com/a/8097798/794473).
      * The RPC method won't solve the fact that bugs might exist in my merge
	  PTE manipulation code.
      * The RPC method also has the drawback that I would need to more
	  frequently perform context switches to perform the actual dput/dget memory
	  ops, since I can't really batch up operations - they must typically be
	  performed synchronously.
   * Write memory code from scratch, using existing functions as a model.

###Possible causes

* Existing code that I rely on might still make invalid assumptions (eg.
`current` is the execution context). At some point, I did a scan of code paths
in existing memory code and found code that assumed executing in the `current`
context. I changed the code to take a general `task_struct` argument, and I'm 
really confident that some memory bugs went away (I can't be 100% sure since the
bugs reduced in frequency drastically, but the bugs still showed up
*sometimes*).
* My merge code manipulates PTEs heavily, and the linux 4 level PT structure is
complicated enough (hugetlb, KSM...), and merge only complicates things. It's
very likely something is wrong with merge, especially since the merge/ps use
case causes the OOPSs to occur.

##Reconsider waitqueue (stability)

I faced some nasty novice bugs with correctly synchronizing on dput/dget and
dret. That code is stable as far as I can tell, but expanded test cases might
reveal bugs. I need to review my waitqueue code and really consider if I used
the correct synchronization strategy.



