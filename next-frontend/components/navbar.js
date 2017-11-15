import Link from 'next/link'

const padding = {
	paddingTop: 5
}
const Header = () =>(

	 <ul>
	 	<div style={padding}>
	 	
	 		<li>
	 			 <Link href="#">
          			<a>UserName</a>
        		</Link>
	 		</li>
	 		
	 		<li>
	 			 <Link href="/view_notes/0">
          			<a>Home</a>
        		</Link>
	 		</li>
	 		<li>
	 			 <Link href="#">
          			<a>Add Note</a>
        		</Link>
	 		</li>
	 		<li>
	 			 <Link href="/settings">
          			<a>Settings</a>
        		</Link>
	 		</li>
	 		
	 		<li>
	 			 <Link href="/logout">
          			<a>Logout</a>
        		</Link>
	 		</li>

	 	
	 	</div>
	 </ul>

	)
export default Header