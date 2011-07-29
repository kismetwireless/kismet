<?xml version="1.0" encoding="ISO-8859-1"?>

<!--
	 Very initial version of a method to convert XML logs to CSV to stop
	 people from whining.  Will get back to this at SOME point.
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 	xmlns:k="http://www.kismetwireless.net/xml">

<xsl:output method="text"/>

<xsl:template match="/">
<xsl:for-each select="k:run/device">
<xsl:value-of select="deviceMac"/>,<xsl:value-of select="firstSeen"/>,<xsl:value-of select="lastSeen"/><xsl:text>&#xa;</xsl:text>
</xsl:for-each>

</xsl:template>
</xsl:stylesheet>
