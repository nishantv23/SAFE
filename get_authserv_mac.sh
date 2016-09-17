#!/bin/bash
ifconfig s1 | grep HWaddr | cut -f13 -d ' '
