--------------------
age-oauth
--------------------
a dead simple oauth helper for ArcGIS Enterprise API users


--------------------
why?
--------------------
oauth 2.0 clients are usually set up for application connections, not developers/analysts. You can use an oauth 2.0 client in ArcGIS Enterprise as a stand-in for developer credentials, but instructions are kind of sparse.  This package gives analysts a simplified Python interface to create an arcgis.gis.GIS object preloaded with access tokens scoped to their user persona, so there are no surprises when you try to do stuff with that GIS object on the portal.  Moreover, it takes care of all token refreshing in the background, so that access to Enterprise is silent and seamless.


--------------------
install
--------------------
*******NOTE: Rename .zip extension to .whl

NOTE: Suggest doing this in your ArcGIS Pro python environment (arcgispro-py3).  The pip install should fall back to a --user install automatically; that's fine/expected. It won't affect operations.

From a command line (PowerShell) that is activated to your desired environment, do:

    pip install age_oauth-0.1.0-py3-none-any.whl


--------------------
dependencies
---------------------
Dependencies should all be met in a typical ArcGIS Pro python environment (arcgispro-py3).

Otherwise, you can grab optional dependencies via pip:

* arcgis-mapping (only if you want the full suite of arcgis API functionality)
* python-dotenv (just convenience, doesn't impact performance)


--------------------
first run
--------------------
On first run, you have to onboard via command line.

With your desired python environment active, do:

    age-oauth init
	
This will prompt you for your Portal OAuth application details.  You'll need to know:

Portal URL
OAuth Client ID
OAuth Client Secret
Verify SSL? [true, false or path to custom CA cert]


--------------------
usage
--------------------
From command line (PowerShell):

    age-oauth login (creates a GIS object)
	
    age-oauth whoami (reports the user persona for which the token serves as an avatar)
	

In Python:

    from age_oauth import get_gis
	
	gis = get_gis()
	
	Then just use gis like any other arcgis.gis.GIS object.