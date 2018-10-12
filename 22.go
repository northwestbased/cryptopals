package cryptopals

import (
	"log"
	"time"
)

/*
Crack an MT19937 seed

Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

    Wait a random number of seconds between, I don't know, 40 and 1000.
    Seeds the RNG with the current Unix timestamp
    Waits a random number of seconds again.
    Returns the first 32 bit output of the RNG.

You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
*/

func WaitThenGenerateNum() uint32 {
	mt := MersenneTwister{}
	wait1 := GetRandomInt(960) + 40
	wait2 := GetRandomInt(960) + 40
	time.Sleep(time.Duration(wait1) * time.Second)
	mt.init(uint32(time.Now().Unix()))
	log.Println("seed done")
	time.Sleep(time.Duration(wait2) * time.Second)
	return mt.ExtractNumber()
}

func CrackSeed(firstNum uint32) {
	t := time.Now().Unix()
	for i := 0; i < 3000; i++ {
		mt := MersenneTwister{}
		seed := uint32(t - int64(i))
		log.Println(seed)

		mt.init(seed)
		if mt.ExtractNumber() == firstNum {
			log.Printf("found that seed!!!!! seed %v %v", seed, i)
			return
		}
	}
	log.Println("did not find seed")
}
