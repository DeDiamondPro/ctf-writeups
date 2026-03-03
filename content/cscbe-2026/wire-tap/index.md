+++
date = '2026-03-03'
title = 'Wire Tap'
tags = ['forensics', 'medium']
+++

Category: Forensics

Difficulty: Medium (464 points)

Author: Maximilien Laenen

## Description

During a physical security audit at NexaMail HQ, a suspicious USB device was recovered from one of the workstations. It had been plugged in without anyone's knowledge. On the workstation itself, forensics found a packet capture that had been running at the time the device was connected.

We don't know what the device was targeting or how long it had been there. Analyse the capture and determine whether any sensitive data was leaked.

## Challenge files

[capture.pcapng](files/capture.pcapng)

## Solution

Opening the capture, we can see that we are capturing data of a USB device. 
The first thing I did was sort the packets by length, most packets are really small, but 1 packet was 172.460 bytes.
This packet contains an image, extracting the packet to a file we can open the (partial) image.

![The partial image](img/1.png)

Looking at the image we can see a link to a login page: `server/63bb50-login`. Unfortunately the image does not contain a 
username or password, so we still have to find this in the dump.

Looking at the dump again and filtering with `usb.src == 1.15.1` (from PC => USB), we can find some packets including "WRTE",
with another packet after that including one or more characters. Piecing this data together (and ignoring the fake flags like
`CSC{d1d_y0u_us3_Cl4ud3_t0_f1nd_m3?_k33p_l00k1ng!_f3225309987939a9}`), we eventually get these 2 terminals commands:
```
lynx:/ $ input text "x1mus"
lynx:/ $ input text "Please0p3nTh3D00R!!!_b6ec8bd3"
```

Inputting this data as username and password on the website gives us the flag.