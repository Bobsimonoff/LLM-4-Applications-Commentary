---
layout:	single
title:	"Exploring ChatGPT Hallucinations and Confabulation through the 6 Degrees of Kevin Bacon Game"
date:	2023-09-08 00:00:00 +0100
author: Bob Simonoff  # as used in `authors.yml`
author_profile: true
header:
  overlay_image: assets/images/2023-09-08-exploring-chatgpt-hallucinations/sebastianneubauer_Doctor_diagnosing_a_hallucinating_female_AI_r_64098c6d-915a-4ebf-8798-a1_crop.png
  overlay_filter: 0.1
  show_overlay_excerpt: false
hidden: true
---

# Exploring ChatGPT Hallucinations and Confabulation through the 6 Degrees of Kevin Bacon Game

## Introduction

I know we’ve all heard about ChatGPT and the issue of hallucinations. **Hallucinations** refer to a model generating fabricated information that has no basis. While large language models are constantly improving, eliminating hallucinations continues to be a challenge. There are prompting techniques that can enhance accuracy and reduce hallucination, including few-shot learning, chain of thought, and tree of thought. But no technique today can fully eliminate hallucinations.

Confabulation involves the model filling in gaps in its knowledge by making up plausible-sounding information. So, while not completely fabricated, confabulated information may be incorrect or unverifiable.

While I was preparing an introductory presentation about ChatGPT, I was experimenting with various prompts to hone my demonstration. I planned to show ChatGPT acting as a brainstorming partner, automotive problem troubleshooter, and language translator. I also wanted to show that ChatGPT has limits to its knowledge and abilities. Ideally, I would be able to show hallucination and confabulation to help the audience understand they should not blindly accept all ChatGpt says. 

One fun demonstration I decided upon involves the game “6 Degrees of Kevin Bacon”. The idea is one person chooses an actor, and then the other player tries to connect that actor to Kevin Bacon through a series of co-stars. You keep linking actors together through shared films until you get to Kevin Bacon.

The following is an example.

## Demonstrating 6 Degrees Of Kevin Bacon

Let’s explore an example of the 6 Degrees of Kevin Bacon Game. The following shows how starting with Mila Kunis you can associate actors through their movie costars until you get to Kevin Bacon:

1. Mila Kunis → “Black Swan” → Natalie Portman
2. Natalie Portman → “Cold Mountain” → Jude Law
3. Jude Law→ “Contagion” → Matt Damon
4. Matt Damon → “The Monuments Men ” → George Clooney 
5. George Clooney → “Ocean’s Thirteen” → Brad Pitt
6. Brad Pitt → “Sleepers” → Kevin Bacon
   
Here is the ChatGPT representation:

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_BsVO71zDWl9OVI_e3SWQQQ.png"/>
  <figcaption>ChatGPT demonstrates that Mila Kunis can be connected to Kevin Bacon in 6 steps.</figcaption>
</figure>

## ChatGPT May Tell You If It Does Not Know

ChatGPT can tell you if it doesn't know about the actor. In the following, I asked ChatGPT to connect a made-up actor named Danny Feznerali to Kevin Bacon. It correctly responds that it can’t find any information about that actor.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_uHH7uTI3NV3PBKQ8eh6SIQ.png"/>
  <figcaption>ChatGPT says it could not find information on the made-up actor Danny Feznerali</figcaption>
</figure>

## ChatGPT and Minor Misspellings

To a limited extent, ChatGPT can correct misspelled names. When I asked ChatGPT to connect Dakota Pfanning to Kevin Bacon, it determined that I likely meant Dakota Fanning and connected her to Kevin Bacon.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_4aocPx7VY-tjUpSaifmyYg.png"/>
  <figcaption>ChatGPT successfully determines that a misspelling of Dakota Fanning can be connected to Kevin Bacon in 2 steps</figcaption>
</figure>

However, if the spelling is a bit more incorrect, as in ‘Dakota Pfenning’, ChatGPT confabulates an answer. Not only does it not tell me who the presumed actor was, but Dakota Fanning nor any actor whose name looks like hers is listed in the cast according to [http://imdb.com](https://medium.com/r/?url=http%3A%2F%2Fimdb.com). Rather than explaining that it does not know who the actor is, as it did with Danny Feznerali, or correcting the spelling error, it confidently gives an incorrect answer. 


<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_m7oqP4nEhcvfpvsKbjWSqQ.png"/>
  <figcaption>ChatGPT hallucinates when asked about a misspelling that is further from Dakota Fanning’s name.</figcaption>
</figure>

If you ask ChatGPT about this, in an attempt to understand its reasoning, you just get an apology.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_LRC6e7Cp6L4jroY-8k5rrA.png"/>
  <figcaption>ChatGPT apologizes for its mistake. </figcaption>
</figure>

This article will dive deeper into hallucinations and confabulations in a few moments.

## ChatGPT Does Not Always Follow Directions

Here, I ask ChatGPT to provide an example connecting an actor or actress to Kevin Bacon through 3 stages. It does select an actor, Tom Hanks but instead of three stages it does it in a single stage through the movie “Apollo 13”

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_M179rPFHg5x8xIey8_8jrQ.png"/>
  <figcaption>ChatGPT connects Tom Hanks to Kevin Bacon in 1 step via the movie "Apollo 13" rather than the requested 3 steps.</figcaption>
</figure>

## ChatGPT Can Answer More Complex Questions

When asked to connect the first actor to ever have played Dracula to Kevin Bacon, it correctly reasons that it first must figure out who the first actor was to play Dracula. After it determines that Bela Lugosi played Dracula in the movie “Abbott and Costello Meet Frankenstein” it then proceeds to follow actors in movies until it gets to Kevin Bacon. Note that ChatGPT determined to not consider Max Schreck as the first Dracula from the film *Nosferatu*, presumably because the character’s name was Count Orlok. The name was changed because the producers could not afford the rights to the name Dracula.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_yZkwat26JWoXr4LC6PT9bQ.png"/>
  <figcaption>ChatGPT correctly determines that the first Dracula was played by Bela Lugosi and connects him to Kevin Bacon in 3 steps </figcaption>
</figure>

## Hallucination and Confabulation — Part 1

Taking this a step further, if asked to connect the first green-eyed actor to have played Dracula to Kevin Bacon, it determines that Christopher Lee meets the criteria, then connects him to Kevin Bacon. Unfortunately, however, Christopher Lee had brown eyes.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_KTQAfhlJO0R_dGnjZ8uvHA.png"/>
  <figcaption>ChatGPT incorrectly says that Christopher Lee’s brown eyes were green </figcaption>
</figure>

But…. When asked about the color of Christopher Lee’s eyes, ChatGPT described them as piercing blue. So, interestingly, ChatGPT treated them as green before and now proclaims they are blue, both of which are incorrect.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_y45_NgdZr2j_iBDq3NpW_w.png"/>
  <figcaption>ChatGPT demonstrates that it seems to know that Lee’s eye color is blue</figcaption>
</figure>

Prompting techniques teach us that the way you ask the question makes a big difference in the outcome. So, if we think about this differently, maybe we can coerce a different result. Let us ask ChatGPT the eye color of all Dracula actors.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_UcF6F1Pi7esJjGtZj7yAkA.png"/>
  <figcaption>ChatGPT lists all Dracula movie actors and their eye color — Lee’s eye color is back to brown!</figcaption>
</figure>

OK assuming this list is correct, none of the actors had green eyes, however, Christopher Lee now has brown eyes. ChatGPT seems to be disagreeing with itself first green, then blue, and now brown.

I would like to dig into the eye color question further to see if we can untangle this mess. We’ve established that ChatGPT thinks it knows Lee’s eye color, but is inconsistent in returning it.

According to the website [Horror Dot Land](https://medium.com/r/?url=https%3A%2F%2Fwww.horror.land%2Fhistory-freaky-vampire-eyes-p1%2F%23%3A~%3Atext%3DDracula%2520%25E2%2580%2593%25201958%2Ceyes%2520look%2520red%2520and%2520angry.). “Christopher Lee’s most famous look, using mini sclera contact lenses. Dark Brown iris with veined sclera that makes the eyes look red and angry.” The site also crops the image, focusing on the eyes to show the brown-eyed Dracula.

If we go to a different website, [WC (WCelebrity.com)](https://medium.com/r/?url=https%3A%2F%2Fwcelebrity.com%2Fchristopher-lee-height-weight-age-biography-husband-more%2F), it tells us that Christopher Lee has brown eyes and a size 11 shoe, if you care.

Another website [romance.com.au](https://www.romance.com.au/we-ranked-our-favourite-draculas-of-all-time/) describes another actor Luke Evans** in “Dracula Untold” (2014) who was “... cut cheekbones. And unruly hair. A five o’clock shadow. **Piercing blue** eyes…”. This statement does appear on the same page as a separate description of Christopher Lee, however, Lee’s eye color is not mentioned.

So, what color were Christopher Lee’s piercing blue/brown/green eyes? Simply looking at pictures online, it is apparent that his eyes are brown.

This reveals how large language models like ChatGPT can make erroneous claims even when they seem knowledgeable. With no reasoning skills or factual grounding, ChatGPT generates plausible-sounding answers based solely on patterns in its training data. The very design of ChatGPT means it has no concept of how it “knows” something — it just predicts the next word in a sequence, regardless of overall paragraph accuracy.

We are not able to review the training data ChatGPT was exposed to or analyze its neural network, so we will never know why ChatGPT responded inconsistently and incorrectly.

This demonstrates that users should be skeptical of ChatGPT’s “facts”. Until models incorporate explainability, reasoning, common sense, and a sense of epistemology, mistakes will persist despite demonstrably impressive capabilities.

## Hallucinations and Confabulation — Part 2

To show that eye color was not a one-time problem, this example will demonstrate the same by exploring actors from the Czech Republic who played Dracula. 

Let’s ask ChatGPT to connect the first Czech actor to have played Dracula with Kevin Bacon. 

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_erhRxj8caKNTBpYUnrWdjQ.png"/>
  <figcaption>ChatGPT claims that the first Czech actor to play Dracula was Max Schreck</figcaption>
</figure>

Max Schreck, interesting, is now Dracula. Even more interesting is that ChatGPT also knows that Max never lived in Czechoslovakia. Max lived in Germany his entire life according to ChatGPT. Nosferatu, however, was filmed in Czechoslovakia.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_OnLJ6pRyO2Ld6cCmvazJog.png"/>
  <figcaption>ChatGPT shows that it also thinks that Max Schreck lived his whole life in Germany</figcaption>
</figure>

Maybe a different tact will yield a Czech actor who played Dracula. Let’s ask for a list of all of the actors from Czechoslovakia who played Dracula. 

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_ieknrekcg7TMtrjDe9vuUQ.png"/>
  <figcaption>ChatGPT claims there are no Czech actors to have played Dracula?!?!</figcaption>
</figure>

ChatGPT claims there are no actors from Czechoslovakia to have played Dracula. But, I wonder if ChatGPT knows otherwise. Let’s ask if Hrabě Drakula is a Czechoslovakian Dracula movie.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_sUJRzFBc_obdGLDPl1NMLg.png"/>
  <figcaption>ChatGPT affirms there there is indeed a Czech Dracula movie where Jiří Hrzán played Dracula</figcaption>
</figure>

Indeed it is! But maybe ChatGPT is confusing the idea of a Czechoslovakian Dracula movie with a Czechoslovakian Dracula actor.

<figure>
  <img src="{{site.url}}/assets/images/2023-09-08-exploring-chatgpt-hallucinations/1_PTyDcnNQiyJ1rJL9-Bq6sQ.png"/>
  <figcaption>ChatGPT demonstrates knowledge that Jiří Hrzán is from Czechoslovakia. </figcaption>
</figure>

Nope, just like the eye color question, ChatGPT seems to have confused itself. It knows the answer but doesn’t return it unless the question is asked differently. Also, Jiří Hrzá was not listed in the list of Dracula actors ChatGPT created earlier. 

## Conclusion

ChatGPT represents an incredibly powerful technology, with new applications being uncovered daily as more explore its diverse capabilities — from law and medicine to wine expertise. However, as shown through examples of hallucination and confabulation, limitations exist in its knowledge and reasoning.

While future versions may overcome current limitations, for now, users should approach ChatGPT’s responses with skepticism and fact-check against authoritative sources. Its answers cannot be taken as absolute truth without capabilities like reasoning, common sense, and self-consistency. Increased transparency into its training data and methodology could also help users gain confidence in ChatGPT’s responses. 

When used with care, ChatGPT can be a helpful assistant, but attribution should be provided if directly using its output. ChatGPT has enormous promise but still requires human discernment. By combining its strengths with the strengths of the human mind, we can leverage this very new and powerful tool.

*Note: [claude.ai](https://medium.com/r/?url=http%3A%2F%2Fclaude.ai) from Anthropic was used for grammar and spelling corrections. It was also used for brainstorming ideas in the conclusion section, however, all words are strictly my own.*

Bob Simonoff is 

* A Senior Principal Software Engineer, Blue Yonder Fellow at [Blue Yonder](http://www.blueyonder.com). 
* A founding member of the [OWASP Top 10 for Large Language Model Applications](https://llmtop10.com). 
* on LinkedIn at [www.linkedin.com/in/bob-simonoff](https://www.linkedin.com/in/bob-simonoff/) 
