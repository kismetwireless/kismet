<?xml version="1.0" encoding="ISO-8859-1"?>

<!--
	 Example of converting XML to CSV filtered by the phy type,
	 in this case, phybtscan
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 	xmlns:k="http://www.kismetwireless.net/xml">

<xsl:output method="text"/>
<xsl:template match="/">
<xsl:text># mac,phy,firstseen,lastseen,packets,linkpackets,datapackets,filteredpackets,errorpackets&#xa;</xsl:text>
<xsl:for-each select="k:run/devices/device[@phy='phybtscan']">
 <xsl:value-of select="deviceMac"/>,<xsl:value-of select="@phy"/>,<xsl:value-of select="firstSeen"/>,<xsl:value-of select="lastSeen"/>,<xsl:value-of select="packets"/>,<xsl:value-of select="packetLink"/>,<xsl:value-of select="packetData"/>,<xsl:value-of select="packetFiltered"/>,<xsl:value-of select="packetError"/><xsl:text>&#xa;</xsl:text>
</xsl:for-each>

</xsl:template>
</xsl:stylesheet>
