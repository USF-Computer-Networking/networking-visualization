# Python DNS Route Lookup
#### by Thomas Oropeza

I decided for my python DNS project I would make an application that stores the route to resolve a DNS lookup. 

The way I do this is by intercepting any DNS packet and resending it. I then can take the result of the resent DNS packet and save the route that it took. I also added a helpful CLI for the user to interact with the application and see the information that is being stored.

These are the supported commands by the CLI:
### Available actions
*     -h (Help)
*     ls (Lists all of the available DNS Routes)
*     route <domain> (Prints the DNS route for the given domain)
*     graph (Shows the graph of counted packets)

It is interesting to see how many steps are taken to resolve certain domains over others. For example, when running this application in my house where there are multiple local devices using DNS I notice they resolve much quicker than DNS packets that are coming for outside.
