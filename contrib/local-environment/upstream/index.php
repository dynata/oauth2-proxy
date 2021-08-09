<!DOCTYPE html>
<html>
    <head></head>
    <title>Choose an application from application list</title>
    <body>
        <ul>
            <?php
                $apps = array(
					"Local App1" => "http://localhost:8000/index-localhost.html",
					"Remote App1" => "http://upstream-app.localhost:8000/index-docker.html"
				);
                foreach ($apps as $key => $app) {
                    echo "<li><a href=".$app."?".$_GET['code']."&".$_GET['session_state'].">".$key."</a></li>";
                }
            ?>
        </ul>
    </php>
    </body>
</html>