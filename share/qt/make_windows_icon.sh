#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/tughlaq.ico

convert ../../src/qt/res/icons/tughlaq-16.png ../../src/qt/res/icons/tughlaq-32.png ../../src/qt/res/icons/tughlaq-48.png ${ICON_DST}
